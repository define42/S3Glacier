package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
)

// LoadCertBundleFromPEM parses one or more certificate PEM blocks for CA trust.
// It rejects decoded blocks whose type is not CERTIFICATE, invalid certificate
// DER, and bundles with no certificates. Non-PEM text is skipped by encoding/pem.
func LoadCertBundleFromPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	certificates := []*x509.Certificate{}
	var block *pem.Block
	block, pemBytes = pem.Decode(pemBytes)
	for ; block != nil; block, pemBytes = pem.Decode(pemBytes) {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		} else {
			return nil, fmt.Errorf("invalid pem block type: %s", block.Type)
		}
	}

	if len(certificates) == 0 {
		return nil, fmt.Errorf("no valid certificates found")
	}

	return certificates, nil
}

// LoadCertBundleFromFile reads a CA certificate bundle and parses it with
// LoadCertBundleFromPEM. File read errors and bundle parsing errors are returned.
func LoadCertBundleFromFile(filename string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return LoadCertBundleFromPEM(b)
}

// ReadCertificates builds the trust pool used to contact the ACME server.
// It adds certificate bundles from /data/ca/ and the required system bundle at
// /etc/ssl/certs/ca-certificates.crt to the system certificate pool.
//
// An unreadable /data/ca/ directory is ignored. An invalid entry in that
// directory or a system pool error causes a panic; failure to load the required
// system bundle terminates the process through log.Fatal.
func ReadCertificates() *x509.CertPool {
	certpool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	caFolder := "/data/ca/"
	files, err := os.ReadDir(caFolder)
	if err != nil {
		// Do not load certificates from a partial directory listing.
		files = nil
		fmt.Println("No Root CA found in:", caFolder)
	}
	for _, file := range files {

		certs, err := LoadCertBundleFromFile(caFolder + file.Name())
		if err != nil {
			fmt.Println("Failed to load Root CA file:", caFolder+file.Name())
			panic(err)
		}

		fmt.Println("Adding CA Root certificate from:", file.Name())
		for _, cert := range certs {
			certpool.AddCert(cert)
		}
	}

	// Read system default Root CA
	defaultCaFile := "/etc/ssl/certs/ca-certificates.crt"
	certs, err := LoadCertBundleFromFile(defaultCaFile)
	if err != nil {
		fmt.Println("Failed to load default Root CA file:", defaultCaFile)
		log.Fatal(err)
	}

	fmt.Println("Adding default CA Root certificate from:", defaultCaFile)
	for _, cert := range certs {
		certpool.AddCert(cert)
	}
	return certpool
}

// HTTPSACME obtains and manages certificates for domainNames, serves mux over
// TLS, and serves ACME challenges and HTTPS redirects on the HTTP listener.
// A nil mux selects http.DefaultServeMux. It blocks while serving HTTPS and
// returns certificate management, listener setup, or HTTPS serving errors.
//
// Call it once during process startup: it configures CertMagic globals and
// shared listeners. Certificate state is stored in /data/acme/; ACME server
// trust comes from ReadCertificates. HTTPPort and HTTPSPort default to 80 and
// 443 and are independent of the executable's SERVER_PORT setting.
func HTTPSACME(domainNames []string, mux http.Handler, acme_server string) error {
	ctx := context.Background()

	if mux == nil {
		mux = http.DefaultServeMux
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.CA = acme_server
	certmagic.Default.Storage = &certmagic.FileStorage{Path: "/data/acme/"}
	certmagic.DefaultACME.TrustedRoots = ReadCertificates()

	cfg := certmagic.NewDefault()

	err := cfg.ManageSync(ctx, domainNames)
	if err != nil {
		return err
	}

	httpWg.Add(1)
	defer httpWg.Done()

	// if we haven't made listeners yet, do so now,
	// and clean them up when all servers are done
	lnMu.Lock()
	if httpLn == nil && httpsLn == nil {
		httpLn, err = net.Listen("tcp", fmt.Sprintf(":%d", HTTPPort))
		if err != nil {
			lnMu.Unlock()
			return err
		}

		tlsConfig := cfg.TLSConfig()
		tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

		httpsLn, err = tls.Listen("tcp", fmt.Sprintf(":%d", HTTPSPort), tlsConfig)
		if err != nil {
			httpLn.Close()
			httpLn = nil
			lnMu.Unlock()
			return err
		}

		go func() {
			httpWg.Wait()
			lnMu.Lock()
			httpLn.Close()
			httpsLn.Close()
			lnMu.Unlock()
		}()
	}
	hln, hsln := httpLn, httpsLn
	lnMu.Unlock()

	// create HTTP/S servers that are configured
	// with sane default timeouts and appropriate
	// handlers (the HTTP server solves the HTTP
	// challenge and issues redirects to HTTPS,
	// while the HTTPS server simply serves the
	// user's handler)
	httpServer := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		BaseContext:       func(listener net.Listener) context.Context { return ctx },
	}
	if len(cfg.Issuers) > 0 {
		if am, ok := cfg.Issuers[0].(*certmagic.ACMEIssuer); ok {
			httpServer.Handler = am.HTTPChallengeHandler(http.HandlerFunc(httpRedirectHandler))
		}
	}
	httpsServer := &http.Server{
		ReadHeaderTimeout: 10000 * time.Second,
		ReadTimeout:       30000 * time.Second,
		// The router arms response write deadlines when output starts. A
		// whole-request WriteTimeout would also limit upload body buffering.
		IdleTimeout: 50000 * time.Minute,
		Handler:     mux,
		BaseContext: func(listener net.Listener) context.Context { return ctx },
	}
	httpsServer.SetKeepAlivesEnabled(false)

	log.Printf("%v Serving HTTP->HTTPS on %s and %s",
		domainNames, hln.Addr(), hsln.Addr())

	go httpServer.Serve(hln)
	return httpsServer.Serve(hsln)
}

func httpRedirectHandler(w http.ResponseWriter, r *http.Request) {
	toURL := "https://"

	// since we redirect to the standard HTTPS port, we
	// do not need to include it in the redirect URL
	requestHost := hostOnly(r.Host)

	toURL += requestHost
	toURL += r.URL.RequestURI()

	// get rid of this disgusting unencrypted HTTP connection 🤢
	w.Header().Set("Connection", "close")

	http.Redirect(w, r, toURL, http.StatusMovedPermanently)
}

// hostOnly returns only the host portion of hostport.
// If there is no port or if there is an error splitting
// the port off, the whole input string is returned.
func hostOnly(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // OK; probably had no port to begin with
	}
	return host
}

const (
	// HTTPChallengePort identifies the standard ACME HTTP-01 challenge port.
	HTTPChallengePort = 80

	// TLSALPNChallengePort identifies the standard ACME TLS-ALPN-01 challenge port.
	TLSALPNChallengePort = 443
)

var (
	// HTTPPort controls HTTPSACME's HTTP challenge and redirect listener.
	// The executable leaves it at 80; SERVER_PORT does not change it.
	HTTPPort = 80

	// HTTPSPort controls HTTPSACME's TLS listener.
	// The executable leaves it at 443; SERVER_PORT does not change it.
	HTTPSPort = 443
)

// Variables for conveniently serving HTTPS.
var (
	httpLn, httpsLn net.Listener
	lnMu            sync.Mutex
	httpWg          sync.WaitGroup
)

// Maximum size for the stack trace when recovering from panics.
const stackTraceBufferSize = 1024 * 128
