// Copyright 2013-2015 Apcera Inc. All rights reserved.

package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	"sync"

	kubeclient "mnk.ee/kubeclient/client"
)

type route struct {
	remoteID   string
	didSolicit bool
	url        *url.URL
}

type connectInfo struct {
	Verbose  bool   `json:"verbose"`
	Pedantic bool   `json:"pedantic"`
	User     string `json:"user,omitempty"`
	Pass     string `json:"pass,omitempty"`
	TLS      bool   `json:"tls_required"`
	Name     string `json:"name"`
}

const conProto = "CONNECT %s" + _CRLF_

// Lock should be held entering here.
func (c *client) sendConnect(tlsRequired bool) {
	var user, pass string
	if userInfo := c.route.url.User; userInfo != nil {
		user = userInfo.Username()
		pass, _ = userInfo.Password()
	}
	cinfo := connectInfo{
		Verbose:  false,
		Pedantic: false,
		User:     user,
		Pass:     pass,
		TLS:      tlsRequired,
		Name:     c.srv.info.ID,
	}
	b, err := json.Marshal(cinfo)
	if err != nil {
		Errorf("Error marshalling CONNECT to route: %v\n", err)
		c.closeConnection()
		return
	}
	c.bw.WriteString(fmt.Sprintf(conProto, b))
	c.bw.Flush()
}

// Process the info message if we are a route.
func (c *client) processRouteInfo(info *Info) {
	c.mu.Lock()
	if c.route == nil {
		c.mu.Unlock()
		return
	}
	c.route.remoteID = info.ID

	// Check to see if we have this remote already registered.
	// This can happen when both servers have routes to each other.
	s := c.srv
	c.mu.Unlock()

	if s.addRoute(c) {
		c.Debugf("Registering remote route %q", info.ID)
		// Send our local subscriptions to this route.
		s.sendLocalSubsToRoute(c)
	} else {
		c.Debugf("Detected duplicate remote route %q", info.ID)
		c.closeConnection()
	}
}

// This will send local subscription state to a new route connection.
// FIXME(dlc) - This could be a DOS or perf issue with many clients
// and large subscription space. Plus buffering in place not a good idea.
func (s *Server) sendLocalSubsToRoute(route *client) {
	b := bytes.Buffer{}

	s.mu.Lock()
	if s.routes[route.cid] == nil {

		// We are too early, let createRoute call this function.
		route.mu.Lock()
		route.sendLocalSubs = true
		route.mu.Unlock()

		s.mu.Unlock()

		return
	}

	for _, client := range s.clients {
		client.mu.Lock()
		subs := client.subs.All()
		client.mu.Unlock()
		for _, s := range subs {
			if sub, ok := s.(*subscription); ok {
				rsid := routeSid(sub)
				proto := fmt.Sprintf(subProto, sub.subject, sub.queue, rsid)
				b.WriteString(proto)
			}
		}
	}
	s.mu.Unlock()

	route.mu.Lock()
	defer route.mu.Unlock()
	route.bw.Write(b.Bytes())
	route.bw.Flush()

	route.Debugf("Route sent local subscriptions")
}

func (s *Server) createRoute(conn net.Conn, rURL *url.URL) *client {
	didSolicit := rURL != nil
	r := &route{didSolicit: didSolicit}
	c := &client{srv: s, nc: conn, opts: clientOpts{}, typ: ROUTER, route: r}

	// Grab server variables.
	s.mu.Lock()
	info := s.routeInfoJSON
	authRequired := s.routeInfo.AuthRequired
	tlsRequired := s.routeInfo.TLSRequired
	s.mu.Unlock()

	// Grab lock
	c.mu.Lock()

	// Initialize
	c.initClient(tlsRequired)

	c.Debugf("Route connection created")

	// Check for TLS
	if tlsRequired {
		// Copy off the config to add in ServerName if we
		tlsConfig := *s.opts.ClusterTLSConfig

		// If we solicited, we will act like the client, otherwise the server.
		if didSolicit {
			c.Debugf("Starting TLS route client handshake")
			// Specify the ServerName we are expecting.
			host, _, _ := net.SplitHostPort(rURL.Host)
			tlsConfig.ServerName = host
			c.nc = tls.Client(c.nc, &tlsConfig)
		} else {
			c.Debugf("Starting TLS route server handshake")
			c.nc = tls.Server(c.nc, &tlsConfig)
		}

		conn := c.nc.(*tls.Conn)

		// Setup the timeout
		ttl := secondsToDuration(s.opts.ClusterTLSTimeout)
		time.AfterFunc(ttl, func() { tlsTimeout(c, conn) })
		conn.SetReadDeadline(time.Now().Add(ttl))

		c.mu.Unlock()
		if err := conn.Handshake(); err != nil {
			c.Debugf("TLS route handshake error: %v", err)
			c.sendErr("Secure Connection - TLS Required")
			c.closeConnection()
			return nil
		}
		// Reset the read deadline
		conn.SetReadDeadline(time.Time{})

		// Re-Grab lock
		c.mu.Lock()

		// Rewrap bw
		c.bw = bufio.NewWriterSize(c.nc, s.opts.BufSize)

		// Do final client initialization

		// Set the Ping timer
		c.setPingTimer()

		// Spin up the read loop.
		go c.readLoop()

		c.Debugf("TLS handshake complete")
		cs := conn.ConnectionState()
		c.Debugf("TLS version %s, cipher suite %s", tlsVersion(cs.Version), tlsCipher(cs.CipherSuite))
	}

	// Queue Connect proto if we solicited the connection.
	if didSolicit {
		r.url = rURL
		c.Debugf("Route connect msg sent")
		c.sendConnect(tlsRequired)
	}

	// Send our info to the other side.
	s.sendInfo(c, info)

	// Check for Auth required state for incoming connections.
	if authRequired && !didSolicit {
		ttl := secondsToDuration(s.opts.ClusterAuthTimeout)
		c.setAuthTimer(ttl)
	}

	// Unlock to register.
	c.mu.Unlock()

	// Register with the server.
	s.mu.Lock()
	s.routes[c.cid] = c
	s.mu.Unlock()

	// Now that the route is registered, we need to make sure that
	// the send of the local subs was not done too early (from
	// processRouteInfo). If it was, then send again.
	c.mu.Lock()
	sendLocalSubs := c.sendLocalSubs
	c.mu.Unlock()

	if sendLocalSubs {
		s.sendLocalSubsToRoute(c)
	}

	return c
}

const (
	_CRLF_  = "\r\n"
	_EMPTY_ = ""
	_SPC_   = " "
)

const (
	subProto   = "SUB %s %s %s" + _CRLF_
	unsubProto = "UNSUB %s%s" + _CRLF_
)

// FIXME(dlc) - Make these reserved and reject if they come in as a sid
// from a client connection.

const (
	RSID  = "RSID"
	QRSID = "QRSID"

	RSID_CID_INDEX   = 1
	RSID_SID_INDEX   = 2
	EXPECTED_MATCHES = 3
)

// FIXME(dlc) - This may be too slow, check at later date.
var qrsidRe = regexp.MustCompile(`QRSID:(\d+):([^\s]+)`)

func (s *Server) routeSidQueueSubscriber(rsid []byte) (*subscription, bool) {
	if !bytes.HasPrefix(rsid, []byte(QRSID)) {
		return nil, false
	}
	matches := qrsidRe.FindSubmatch(rsid)
	if matches == nil || len(matches) != EXPECTED_MATCHES {
		return nil, false
	}
	cid := uint64(parseInt64(matches[RSID_CID_INDEX]))

	s.mu.Lock()
	client := s.clients[cid]
	s.mu.Unlock()

	if client == nil {
		return nil, true
	}
	sid := matches[RSID_SID_INDEX]

	if sub, ok := (client.subs.Get(sid)).(*subscription); ok {
		return sub, true
	}
	return nil, true
}

func routeSid(sub *subscription) string {
	var qi string
	if len(sub.queue) > 0 {
		qi = "Q"
	}
	return fmt.Sprintf("%s%s:%d:%s", qi, RSID, sub.client.cid, sub.sid)
}

func (s *Server) addRoute(c *client) bool {
	id := c.route.remoteID
	s.mu.Lock()
	remote, exists := s.remotes[id]
	if !exists {
		s.remotes[id] = c
	}
	s.mu.Unlock()

	if exists && c.route.didSolicit {
		// upgrade to solicited?
		remote.mu.Lock()
		remote.route = c.route
		uid := c.route.url.Query().Get("uid")
		remote.mu.Unlock()
		if uid != "" {
			s.routeConnect <- DynamicRoute{
				UID:    uid,
				Client: remote,
			}
		}
	}

	return !exists
}

func (s *Server) broadcastToRoutes(proto string) {
	var arg []byte
	if atomic.LoadInt32(&trace) == 1 {
		arg = []byte(proto[:len(proto)-LEN_CR_LF])
	}
	s.mu.Lock()
	for _, route := range s.routes {
		// FIXME(dlc) - Make same logic as deliverMsg
		route.mu.Lock()
		route.bw.WriteString(proto)
		route.bw.Flush()
		route.mu.Unlock()
		route.traceOutOp("", arg)
	}
	s.mu.Unlock()
}

// broadcastSubscribe will forward a client subscription
// to all active routes.
func (s *Server) broadcastSubscribe(sub *subscription) {
	if s.numRoutes() == 0 {
		return
	}
	rsid := routeSid(sub)
	proto := fmt.Sprintf(subProto, sub.subject, sub.queue, rsid)
	s.broadcastToRoutes(proto)
}

// broadcastUnSubscribe will forward a client unsubscribe
// action to all active routes.
func (s *Server) broadcastUnSubscribe(sub *subscription) {
	if s.numRoutes() == 0 {
		return
	}
	rsid := routeSid(sub)
	maxStr := _EMPTY_
	// Set max if we have it set and have not tripped auto-unsubscribe
	if sub.max > 0 && sub.nm < sub.max {
		maxStr = fmt.Sprintf(" %d", sub.max)
	}
	proto := fmt.Sprintf(unsubProto, rsid, maxStr)
	s.broadcastToRoutes(proto)
}

func (s *Server) routeAcceptLoop(ch chan struct{}) {
	hp := fmt.Sprintf("%s:%d", s.opts.ClusterHost, s.opts.ClusterPort)
	Noticef("Listening for route connections on %s", hp)
	l, e := net.Listen("tcp", hp)
	if e != nil {
		Fatalf("Error listening on router port: %d - %v", s.opts.Port, e)
		return
	}

	// Let them know we are up
	close(ch)

	// Setup state that can enable shutdown
	s.mu.Lock()
	s.routeListener = l
	s.mu.Unlock()

	tmpDelay := ACCEPT_MIN_SLEEP

	for s.isRunning() {
		conn, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				Debugf("Temporary Route Accept Errorf(%v), sleeping %dms",
					ne, tmpDelay/time.Millisecond)
				time.Sleep(tmpDelay)
				tmpDelay *= 2
				if tmpDelay > ACCEPT_MAX_SLEEP {
					tmpDelay = ACCEPT_MAX_SLEEP
				}
			} else if s.isRunning() {
				Noticef("Accept error: %v", err)
			}
			continue
		}
		tmpDelay = ACCEPT_MIN_SLEEP
		go s.createRoute(conn, nil)
	}
	Debugf("Router accept loop exiting..")
	s.done <- true
}

// StartRouting will start the accept loop on the cluster host:port
// and will actively try to connect to listed routes.
func (s *Server) StartRouting() {
	// Check for TLSConfig
	tlsReq := s.opts.ClusterTLSConfig != nil
	info := Info{
		ID:           s.info.ID,
		Version:      s.info.Version,
		Host:         s.opts.ClusterHost,
		Port:         s.opts.ClusterPort,
		AuthRequired: false,
		TLSRequired:  tlsReq,
		SSLRequired:  tlsReq,
		TLSVerify:    tlsReq,
		MaxPayload:   s.info.MaxPayload,
	}
	// Check for Auth items
	if s.opts.ClusterUsername != "" {
		info.AuthRequired = true
	}
	s.routeInfo = info
	// Generate the info json
	b, err := json.Marshal(info)
	if err != nil {
		Fatalf("Error marshalling Route INFO JSON: %+v\n", err)
	}
	s.routeInfoJSON = []byte(fmt.Sprintf("INFO %s %s", b, CR_LF))

	// Spin up the accept loop
	ch := make(chan struct{})
	go s.routeAcceptLoop(ch)
	<-ch

	// Solicit Routes if needed.
	s.solicitRoutes()

	go s.solicitDynamicRoutes()
}

func (s *Server) reConnectToRoute(rUrl *url.URL) {
	time.Sleep(DEFAULT_ROUTE_RECONNECT)
	s.connectToRoute(rUrl)
}

func (s *Server) connectToRoute(rUrl *url.URL) {
	attempts := uint64(0)
	waitTime := DEFAULT_ROUTE_CONNECT

	for s.isRunning() && rUrl != nil {
		if IsDynamicRoute(rUrl) && !s.dynamicRoutes.IsRegistered(rUrl) {
			Noticef("Dynamic route has been removed, not attempting reconnect: %s", rUrl.Host)
			return
		}
		attempts++
		Debugf("Trying to connect to route on %s, attempt %d", rUrl.Host, attempts)
		conn, err := net.DialTimeout("tcp", rUrl.Host, DEFAULT_ROUTE_DIAL)
		if err != nil {
			Debugf("Error trying to connect to route: %v", err)
			select {
			case <-s.rcQuit:
				return
			case <-time.After(waitTime):
				if waitTime < MAX_BACKOFF_TIME {
					waitTime = waitTime * 2
					if waitTime > MAX_BACKOFF_TIME {
						waitTime = MAX_BACKOFF_TIME
					}
				}
				continue
			}
		}
		// We have a route connection here.
		// Go ahead and create it and exit this func.
		client := s.createRoute(conn, rUrl)
		uid := rUrl.Query().Get("uid")
		if uid != "" {
			s.routeConnect <- DynamicRoute{
				UID:    uid,
				Client: client,
			}
		}
		return
	}
}

func (c *client) isSolicitedRoute() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.typ == ROUTER && c.route != nil && c.route.didSolicit
}

func (s *Server) solicitRoutes() {
	for _, r := range s.opts.Routes {
		go s.connectToRoute(r)
	}
}

func (s *Server) solicitDynamicRoutes() {
	service := s.opts.KubeServiceStr
	namespace := s.opts.KubeNamespaceStr
	portName := s.opts.KubePortNameStr

	if service == "" || namespace == "" || portName == "" {
		Debugf("Kubernetes is not configured")
		return
	}

	if s.opts.ClusterUsername != "" && s.opts.ClusterPassword != "" {
		s.clusterUser = url.UserPassword(s.opts.ClusterUsername, s.opts.ClusterPassword)
	}

	srvName := fmt.Sprintf("%s.%s.svc.cluster.local", service, namespace)

	s.dynamicRoutes = DynamicRouteRegistry{
		routesByUID: map[string]*DynamicRoute{},
	}
	s.routeConnect = make(chan DynamicRoute)
	s.routeDiscover = make(chan kubeclient.V1Endpoints)

	selfIPs := getInterfaceIPs()
	go s.solicitKubeRoutes(namespace, service, portName, "tcp", srvName)

	addRoute := func(addr *kubeclient.V1EndpointAddress, port int32, resourceVersion string) {
		uid := addr.TargetRef.UID
		dr, ok := s.dynamicRoutes.Get(uid)

		if ok {
			Debugf("Not adding host already registered: %s", uid)
			dr.ResourceVersion = resourceVersion
			return
		}
		ip := addr.IP
		if s.opts.ClusterPort == int(port) && isIpInList(selfIPs, []net.IP{net.ParseIP(ip)}) {
			Debugf("Not adding self referencing address: %s", ip)
			return
		}
		params := url.Values{}
		params.Set("uid", uid)
		r := &url.URL{
			Scheme:   "nats-route",
			User:     s.clusterUser,
			Host:     net.JoinHostPort(ip, strconv.FormatUint(uint64(port), 10)),
			RawQuery: params.Encode(),
		}
		Debugf("Adding route %s to %s:%d", uid, ip, port)
		s.dynamicRoutes.Register(&DynamicRoute{
			UID:             uid,
			ResourceVersion: resourceVersion,
		})
		go s.connectToRoute(r)
	}

	for s.isRunning() {
		select {
		case dr := <-s.routeConnect:
			existing, ok := s.dynamicRoutes.Get(dr.UID)
			if ok {
				existing.Client = dr.Client
			} else {
				Noticef("Disconnecting %s, was unregistered in race with connect", dr.UID)
				dr.Client.closeConnection()
			}
		case e := <-s.routeDiscover:
			resourceVersion := e.Metadata.ResourceVersion
			for i := range e.Subsets {
				port := int32(s.opts.ClusterPort)
				for j := range e.Subsets[i].Ports {
					if e.Subsets[i].Ports[j].Name == portName {
						port = e.Subsets[i].Ports[j].Port
					}
				}
				for j := range e.Subsets[i].NotReadyAddresses {
					addRoute(e.Subsets[i].NotReadyAddresses[j], port, resourceVersion)
				}
				for j := range e.Subsets[i].Addresses {
					addRoute(e.Subsets[i].Addresses[j], port, resourceVersion)
				}
			}
			s.dynamicRoutes.EvictStale(resourceVersion)
		}
	}
	close(s.routeDiscover)
	close(s.routeConnect)
}

type DynamicRoute struct {
	UID    string
	Client *client

	ResourceVersion string
}

type DynamicRouteRegistry struct {
	routesByUID map[string]*DynamicRoute
	sync.Mutex
}

func (drr *DynamicRouteRegistry) Register(dr *DynamicRoute) {
	drr.Lock()
	drr.routesByUID[dr.UID] = dr
	drr.Unlock()
}

func (drr *DynamicRouteRegistry) Get(uid string) (*DynamicRoute, bool) {
	drr.Lock()
	dr, exists := drr.routesByUID[uid]
	drr.Unlock()
	return dr, exists
}

func (drr *DynamicRouteRegistry) IsRegistered(url *url.URL) bool {
	if url == nil {
		return false
	}

	uid := url.Query().Get("uid")
	if uid == "" {
		return false
	}
	drr.Lock()
	_, exists := drr.routesByUID[uid]
	drr.Unlock()
	return exists
}

func (drr *DynamicRouteRegistry) Unregister(uid string) {
	drr.Lock()
	delete(drr.routesByUID, uid)
	drr.Unlock()
}

func (drr *DynamicRouteRegistry) EvictStale(resourceVersion string) {
	drr.Lock()
	for uid, r := range drr.routesByUID {
		if r.ResourceVersion != resourceVersion {
			Debugf("Removing route %s", uid)
			delete(drr.routesByUID, uid)
			// prevent reconnections...
			client := r.Client
			if client != nil {
				client.closeConnection()
			}
		}
	}
	drr.Unlock()
}

func IsDynamicRoute(url *url.URL) bool {
	return url.Query().Get("uid") != ""
}

func (s *Server) solicitKubeRoutes(namespace, serviceName, portName, protocol, name string) {
	k, err := kubeclient.NewInCluster()
	if err != nil {
		Errorf("Error configuring kubernetes cluster client for endpoints: namespace = %s, service = %s, port = %s: %s", namespace, serviceName, portName, err)
		panic(err)
		return
	}

	params := &kubeclient.ReadNamespacedEndpointsParams{
		Namespace: namespace,
		Name:      serviceName,
	}
	q, errQ := k.ReadNamespacedEndpoints(params)
	if errQ != nil {
		Errorf("Error contacting kubernetes cluster for endpoints: namespace = %s, service = %s, port = %s: %s", namespace, serviceName, portName, errQ)
		panic(errQ)
		return
	}
	s.routeDiscover <- *q

	Debugf("read namespaced endpoints: %+v", q)
	watch := &kubeclient.WatchNamespacedEndpointsParams{
		Namespace:       namespace,
		Name:            serviceName,
		ResourceVersion: q.Metadata.ResourceVersion,
		TimeoutSeconds:  10,
		Watch:           true,
	}
	callback := func(k *kubeclient.Kubernetes, we *kubeclient.EndpointsWatchEvent) error {
		Debugf("Got watch event: type=%s object=%+v object.subsets=%+v", we.Type, we.Object, we.Object.Subsets)
		watch.ResourceVersion = we.Object.Metadata.ResourceVersion
		if we.Type == "ADDED" || we.Type == "MODIFIED" {
			s.routeDiscover <- we.Object
		}
		return nil
	}

	for s.isRunning() {
		if err := k.WatchNamespacedEndpoints(watch, callback); err != nil {
			Errorf("Error contacting kubernetes cluster for endpoints watch: namespace = %s, service = %s, port = %s: %s", namespace, serviceName, portName, err)
			time.Sleep(1 * time.Minute)
		}
	}
}

func (s *Server) numRoutes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.routes)
}
