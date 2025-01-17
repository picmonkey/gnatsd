// Copyright 2015 Apcera Inc. All rights reserved.

package test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/gnatsd/server"
	"github.com/nats-io/nats"
)

func TestTLSConnection(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/tls.conf")
	defer srv.Shutdown()

	endpoint := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	nurl := fmt.Sprintf("nats://%s:%s@%s/", opts.Username, opts.Password, endpoint)
	nc, err := nats.Connect(nurl)
	if err == nil {
		t.Fatalf("Expected error trying to connect to secure server")
	}

	// Do simple SecureConnect
	nc, err = nats.SecureConnect(fmt.Sprintf("nats://%s/", endpoint))
	if err == nil {
		t.Fatalf("Expected error trying to connect to secure server with no auth")
	}

	// Now do more advanced checking, verifying servername and using rootCA.
	// Setup our own TLSConfig using RootCA from our self signed cert.
	rootPEM, err := ioutil.ReadFile("./configs/certs/ca.pem")
	if err != nil || rootPEM == nil {
		t.Fatalf("failed to read root certificate")
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		t.Fatalf("failed to parse root certificate")
	}

	config := &tls.Config{
		ServerName: opts.Host,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	copts := nats.DefaultOptions
	copts.Url = nurl
	copts.Secure = true
	copts.TLSConfig = config

	nc, err = copts.Connect()
	if err != nil {
		t.Fatalf("Got an error on Connect with Secure Options: %+v\n", err)
	}
	defer nc.Close()

	subj := "foo-tls"
	sub, _ := nc.SubscribeSync(subj)

	nc.Publish(subj, []byte("We are Secure!"))
	nc.Flush()
	nmsgs, _ := sub.QueuedMsgs()
	if nmsgs != 1 {
		t.Fatalf("Expected to receive a message over the TLS connection")
	}
}

func TestTLSClientCertificate(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/tlsverify.conf")
	defer srv.Shutdown()

	nurl := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)

	_, err := nats.Connect(nurl)
	if err == nil {
		t.Fatalf("Expected error trying to connect to secure server without a certificate")
	}

	_, err = nats.SecureConnect(nurl)
	if err == nil {
		t.Fatalf("Expected error trying to secure connect to secure server without a certificate")
	}

	// Load client certificate to sucessfully connect.
	certFile := "./configs/certs/client-cert.pem"
	keyFile := "./configs/certs/client-key.pem"
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("error parsing X509 certificate/key pair: %v", err)
	}

	// Load in root CA for server verification
	rootPEM, err := ioutil.ReadFile("./configs/certs/ca.pem")
	if err != nil || rootPEM == nil {
		t.Fatalf("failed to read root certificate")
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		t.Fatalf("failed to parse root certificate")
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   opts.Host,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	copts := nats.DefaultOptions
	copts.Url = nurl
	copts.Secure = true
	copts.TLSConfig = config

	nc, err := copts.Connect()
	if err != nil {
		t.Fatalf("Got an error on Connect with Secure Options: %+v\n", err)
	}
	nc.Flush()
	defer nc.Close()
}

func TestTLSConnectionTimeout(t *testing.T) {
	opts := LoadConfig("./configs/tls.conf")
	opts.TLSTimeout = 0.25

	srv := RunServer(opts)
	defer srv.Shutdown()

	// Dial with normal TCP
	endpoint := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	conn, err := net.Dial("tcp", endpoint)
	if err != nil {
		t.Fatalf("Could not connect to %q", endpoint)
	}
	defer conn.Close()

	// Read deadlines
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	// Read the INFO string.
	br := bufio.NewReader(conn)
	info, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read INFO - %v", err)
	}
	if !strings.HasPrefix(info, "INFO ") {
		t.Fatalf("INFO response incorrect: %s\n", info)
	}
	wait := time.Duration(opts.TLSTimeout * float64(time.Second))
	time.Sleep(wait)
	// Read deadlines
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	tlsErr, err := br.ReadString('\n')
	if err == nil && !strings.Contains(tlsErr, "-ERR 'Secure Connection - TLS Required") {
		t.Fatalf("TLS Timeout response incorrect: %q\n", tlsErr)
	}
}

func stressConnect(t *testing.T, wg *sync.WaitGroup, errCh chan error, url string, index int) {
	defer wg.Done()

	subName := fmt.Sprintf("foo.%d", index)

	for i := 0; i < 100; i++ {
		nc, err := nats.SecureConnect(url)
		if err != nil {
			errCh <- fmt.Errorf("Unable to create TLS connection: %v\n", err)
			return
		}
		defer nc.Close()

		sub, err := nc.SubscribeSync(subName)
		if err != nil {
			errCh <- fmt.Errorf("Unable to subscribe on '%s': %v\n", subName, err)
			return
		}

		if err := nc.Publish(subName, []byte("secure data")); err != nil {
			errCh <- fmt.Errorf("Unable to send on '%s': %v\n", subName, err)
		}

		if _, err := sub.NextMsg(2 * time.Second); err != nil {
			errCh <- fmt.Errorf("Unable to get next message: %v\n", err)
		}

		nc.Close()
	}

	errCh <- nil
}

func TestTLSStressConnect(t *testing.T) {
	opts, err := server.ProcessConfigFile("./configs/tls.conf")
	if err != nil {
		panic(fmt.Sprintf("Error processing configuration file: %v", err))
	}
	opts.NoSigs, opts.NoLog = true, true

	// For this test, remove the authorization
	opts.Authorization = ""

	// Increase ssl timeout
	opts.TLSTimeout = 2.0

	srv := RunServer(opts)
	defer srv.Shutdown()

	nurl := fmt.Sprintf("nats://%s:%d", opts.Host, opts.Port)

	threadCount := 3

	errCh := make(chan error, threadCount)

	var wg sync.WaitGroup
	wg.Add(threadCount)

	for i := 0; i < threadCount; i++ {
		go stressConnect(t, &wg, errCh, nurl, i)
	}

	wg.Wait()

	var lastError error
	lastError = nil
	for i := 0; i < threadCount; i++ {
		err := <-errCh
		if err != nil {
			lastError = err
		}
	}

	if lastError != nil {
		t.Fatalf("%v\n", lastError)
	}
}
