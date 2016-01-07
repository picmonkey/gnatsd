// Copyright 2012-2015 Apcera Inc. All rights reserved.

package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/nats-io/gnatsd/auth"
	"github.com/nats-io/gnatsd/logger"
	"github.com/nats-io/gnatsd/server"
)

func main() {
	// Server Options
	opts := server.Options{}

	var showVersion bool
	var debugAndTrace bool
	var configFile string
	var showTlsHelp bool

	// Parse flags
	flag.IntVar(&opts.Port, "port", 0, "Port to listen on.")
	flag.IntVar(&opts.Port, "p", 0, "Port to listen on.")
	flag.StringVar(&opts.Host, "addr", "", "Network host to listen on.")
	flag.StringVar(&opts.Host, "a", "", "Network host to listen on.")
	flag.StringVar(&opts.Host, "net", "", "Network host to listen on.")
	flag.BoolVar(&opts.Debug, "D", false, "Enable Debug logging.")
	flag.BoolVar(&opts.Debug, "debug", false, "Enable Debug logging.")
	flag.BoolVar(&opts.Trace, "V", false, "Enable Trace logging.")
	flag.BoolVar(&opts.Trace, "trace", false, "Enable Trace logging.")
	flag.BoolVar(&debugAndTrace, "DV", false, "Enable Debug and Trace logging.")
	flag.BoolVar(&opts.Logtime, "T", true, "Timestamp log entries.")
	flag.BoolVar(&opts.Logtime, "logtime", true, "Timestamp log entries.")
	flag.StringVar(&opts.Username, "user", "", "Username required for connection.")
	flag.StringVar(&opts.Password, "pass", "", "Password required for connection.")
	flag.StringVar(&opts.Authorization, "auth", "", "Authorization token required for connection.")
	flag.IntVar(&opts.HTTPPort, "m", 0, "HTTP Port for /varz, /connz endpoints.")
	flag.IntVar(&opts.HTTPPort, "http_port", 0, "HTTP Port for /varz, /connz endpoints.")
	flag.IntVar(&opts.HTTPSPort, "ms", 0, "HTTPS Port for /varz, /connz endpoints.")
	flag.IntVar(&opts.HTTPSPort, "https_port", 0, "HTTPS Port for /varz, /connz endpoints.")
	flag.StringVar(&configFile, "c", "", "Configuration file.")
	flag.StringVar(&configFile, "config", "", "Configuration file.")
	flag.StringVar(&opts.PidFile, "P", "", "File to store process pid.")
	flag.StringVar(&opts.PidFile, "pid", "", "File to store process pid.")
	flag.StringVar(&opts.LogFile, "l", "", "File to store logging output.")
	flag.StringVar(&opts.LogFile, "log", "", "File to store logging output.")
	flag.BoolVar(&opts.Syslog, "s", false, "Enable syslog as log method.")
	flag.BoolVar(&opts.Syslog, "syslog", false, "Enable syslog as log method..")
	flag.StringVar(&opts.RemoteSyslog, "r", "", "Syslog server addr (udp://localhost:514).")
	flag.StringVar(&opts.RemoteSyslog, "remote_syslog", "", "Syslog server addr (udp://localhost:514).")
	flag.BoolVar(&showVersion, "version", false, "Print version information.")
	flag.BoolVar(&showVersion, "v", false, "Print version information.")
	flag.IntVar(&opts.ProfPort, "profile", 0, "Profiling HTTP port")
	flag.StringVar(&opts.RoutesStr, "routes", "", "Routes to actively solicit a connection.")
	flag.StringVar(&opts.ClusterListenStr, "cluster_listen", "", "Cluster url from which members can solicit routes.")
	flag.StringVar(&opts.KubeServiceStr, "kube_service", "", "Kubernetes service to query for routes.")
	flag.StringVar(&opts.KubeNamespaceStr, "kube_namespace", "", "Kubernetes namespace to query for routes.")
	flag.StringVar(&opts.KubePortNameStr, "kube_port_name", "", "Kubernetes port name to query for routes.")
	flag.BoolVar(&showTlsHelp, "help_tls", false, "TLS help.")
	flag.BoolVar(&opts.TLS, "tls", false, "Enable TLS.")
	flag.BoolVar(&opts.TLSVerify, "tlsverify", false, "Enable TLS with client verification.")
	flag.StringVar(&opts.TLSCert, "tlscert", "", "Server certificate file.")
	flag.StringVar(&opts.TLSKey, "tlskey", "", "Private key for server certificate.")
	flag.StringVar(&opts.TLSCaCert, "tlscacert", "", "Client certificate CA for verification.")

	// Not public per se, will be replaced with dynamic system, but can be used to lower memory footprint when
	// lots of connections present.
	flag.IntVar(&opts.BufSize, "bs", 0, "Read/Write buffer size per client connection.")

	flag.Usage = server.Usage

	flag.Parse()

	// Show version and exit
	if showVersion {
		server.PrintServerAndExit()
	}

	if showTlsHelp {
		server.PrintTlsHelpAndDie()
	}

	// One flag can set multiple options.
	if debugAndTrace {
		opts.Trace, opts.Debug = true, true
	}

	// Process args looking for non-flag options,
	// 'version' and 'help' only for now
	for _, arg := range flag.Args() {
		switch strings.ToLower(arg) {
		case "version":
			server.PrintServerAndExit()
		case "help":
			server.Usage()
		}
	}

	// Parse config if given
	if configFile != "" {
		fileOpts, err := server.ProcessConfigFile(configFile)
		if err != nil {
			server.PrintAndDie(err.Error())
		}
		opts = *server.MergeOptions(fileOpts, &opts)
	}

	// Remove any host/ip that points to itself in Route
	newroutes, err := server.RemoveSelfReference(opts.ClusterPort, opts.Routes)
	if err != nil {
		server.PrintAndDie(err.Error())
	}
	opts.Routes = newroutes

	// Configure TLS based on any present flags
	configureTLS(&opts)

	// Configure cluster opts if explicitly set via flags.
	err = configureClusterOpts(&opts)
	if err != nil {
		server.PrintAndDie(err.Error())
	}

	// Create the server with appropriate options.
	s := server.New(&opts)

	// Configure the authentication mechanism
	configureAuth(s, &opts)

	// Configure the logger based on the flags
	configureLogger(s, &opts)

	// Start things up. Block here until done.
	s.Start()
}

func configureAuth(s *server.Server, opts *server.Options) {
	if opts.Username != "" {
		auth := &auth.Plain{
			Username: opts.Username,
			Password: opts.Password,
		}
		s.SetAuthMethod(auth)
	} else if opts.Authorization != "" {
		auth := &auth.Token{
			Token: opts.Authorization,
		}
		s.SetAuthMethod(auth)
	}
}

func configureLogger(s *server.Server, opts *server.Options) {
	var log server.Logger

	if opts.LogFile != "" {
		log = logger.NewFileLogger(opts.LogFile, opts.Logtime, opts.Debug, opts.Trace, true)
	} else if opts.RemoteSyslog != "" {
		log = logger.NewRemoteSysLogger(opts.RemoteSyslog, opts.Debug, opts.Trace)
	} else if opts.Syslog {
		log = logger.NewSysLogger(opts.Debug, opts.Trace)
	} else {
		colors := true
		// Check to see if stderr is being redirected and if so turn off color
		// Also turn off colors if we're running on Windows where os.Stderr.Stat() returns an invalid handle-error
		stat, err := os.Stderr.Stat()
		if err != nil || (stat.Mode()&os.ModeCharDevice) == 0 {
			colors = false
		}
		log = logger.NewStdLogger(opts.Logtime, opts.Debug, opts.Trace, colors, true)
	}

	s.SetLogger(log, opts.Debug, opts.Trace)
}

func configureTLS(opts *server.Options) {
	// If no trigger flags, ignore the others
	if !opts.TLS && !opts.TLSVerify {
		return
	}
	if opts.TLSCert == "" {
		server.PrintAndDie("TLS Server certificate must be present and valid.")
	}
	if opts.TLSKey == "" {
		server.PrintAndDie("TLS Server private key must be present and valid.")
	}

	tc := server.TLSConfigOpts{}
	tc.CertFile = opts.TLSCert
	tc.KeyFile = opts.TLSKey
	tc.CaFile = opts.TLSCaCert

	if opts.TLSVerify {
		tc.Verify = true
	}
	var err error
	if opts.TLSConfig, err = server.GenTLSConfig(&tc); err != nil {
		server.PrintAndDie(err.Error())
	}
}

func configureClusterOpts(opts *server.Options) error {
	if opts.ClusterListenStr == "" {
		return nil
	}

	clusterUrl, err := url.Parse(opts.ClusterListenStr)
	h, p, err := net.SplitHostPort(clusterUrl.Host)
	if err != nil {
		return err
	}
	opts.ClusterHost = h
	_, err = fmt.Sscan(p, &opts.ClusterPort)
	if err != nil {
		return err
	}

	if clusterUrl.User != nil {
		pass, hasPassword := clusterUrl.User.Password()
		if !hasPassword {
			return fmt.Errorf("Expected cluster password to be set.")
		}
		opts.ClusterPassword = pass

		user := clusterUrl.User.Username()
		opts.ClusterUsername = user
	}

	return nil
}
