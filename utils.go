package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/publicsuffix"
)

var httpClient = &fasthttp.Client{
	ReadTimeout:         30 * time.Second,
	MaxConnsPerHost:     233,
	MaxIdleConnDuration: 15 * time.Minute,
	ReadBufferSize:      1024 * 8,
	Dial: func(addr string) (net.Conn, error) {
		// no suitable address found => ipv6 can not dial to ipv4,..
		hostname, port, err := net.SplitHostPort(addr)
		if err != nil {
			if err1, ok := err.(*net.AddrError); ok && strings.Index(err1.Err, "missing port") != -1 {
				hostname, port, err = net.SplitHostPort(strings.TrimRight(addr, ":") + ":80")
			}
			if err != nil {
				return nil, err
			}
		}
		if port == "" || port == ":" {
			port = "80"
		}
		return fasthttp.DialDualStackTimeout("["+hostname+"]:"+port, 7*time.Second)
	},
}

var errEncodingNotSupported = errors.New("response content encoding not supported")

func getResponseBody(resp *fasthttp.Response) ([]byte, error) {
	var contentEncoding = resp.Header.Peek("Content-Encoding")
	if len(contentEncoding) < 1 {
		return resp.Body(), nil
	}
	if bytes.Equal(contentEncoding, []byte("gzip")) {
		return resp.BodyGunzip()
	}
	if bytes.Equal(contentEncoding, []byte("deflate")) {
		return resp.BodyInflate()
	}
	return nil, errEncodingNotSupported
}

var cacheVerifyMap = map[string]string{}
var cacheVerifyMapLock sync.RWMutex

func verifyPeerCertFunc(Hostname string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if config.skipTLSVerify {
			return nil
		}
		certs := make([]*x509.Certificate, len(rawCerts))
		for i, c := range rawCerts {
			var err error
			certs[i], err = x509.ParseCertificate(c)
			if err != nil {
				return err
			}
		}
		opts := x509.VerifyOptions{
			DNSName:       Hostname,
			Intermediates: x509.NewCertPool(),
		}

		for i, cert := range certs {
			if i == 0 {
				continue
			}
			opts.Intermediates.AddCert(cert)
		}
		cert := certs[0]
		_, err := cert.Verify(opts)
		if err == nil {
			return nil
		}

		cacheVerifyMapLock.RLock()
		d, ok := cacheVerifyMap[Hostname]
		cacheVerifyMapLock.RUnlock()
		if ok {
			opts.DNSName = d
			_, err = cert.Verify(opts)
			if err == nil {
				return nil
			}
		}

		aliasDomains, ok := certDomainAliasMap[Hostname]
		if ok {
			for _, d = range aliasDomains {
				opts.DNSName = d
				_, err = cert.Verify(opts)
				if err == nil {
					cacheVerifyMapLock.Lock()
					cacheVerifyMap[Hostname] = d
					cacheVerifyMapLock.Unlock()
					return nil
				}
			}
		}
		log.Printf("Cert invalid: Remote certificate is for %s, not %s\n", cert.DNSNames, Hostname)
		return err
	}
}

// from goproxy
func init() {
	// Avoid deterministic random numbers
	rand.Seed(time.Now().UnixNano())
}

var goproxySignerVersion = ":goroxy1"
var certCache = map[string]*tls.Certificate{}
var certCacheLock sync.RWMutex
var defaultTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
}

func genCertHostnames(hostname string) ([]string, string) {
	mainDomain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return []string{hostname}, hostname
	}
	if mainDomain == hostname {
		return []string{hostname, "*." + hostname}, hostname
	}
	var hostnames []string
	start := 0
	for {
		index := strings.IndexByte(hostname[start:], byte('.'))
		if index == -1 {
			break
		}
		start += index + 1
		subdomain := hostname[start:]
		hostnames = append(hostnames, "*."+subdomain)
		if subdomain == mainDomain {
			hostnames = append(hostnames, subdomain)
			break
		}
	}
	hostnames = append(hostnames, "*."+hostname)
	return hostnames, hostnames[0]
}

func TLSConfigFromCA(ca *tls.Certificate, hostname string) (*tls.Config, error) {
	var err error
	hostnames, key := genCertHostnames(hostname)
	certCacheLock.RLock()
	cert, ok := certCache[key]
	certCacheLock.RUnlock()
	config := *defaultTLSConfig
	if ok == false {
		cert, err = signHost(*ca, hostnames)
		if err != nil {
			return nil, err
		}
		for _, key = range hostnames {
			certCacheLock.Lock()
			certCache[key] = cert
			certCacheLock.Unlock()
		}
	}
	config.Certificates = append(config.Certificates, *cert)
	return &config, nil
}

func signHost(ca tls.Certificate, hosts []string) (cert *tls.Certificate, err error) {
	var x509ca *x509.Certificate

	// Use the provided ca and not the global GoproxyCa for certificate generation.
	if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return
	}
	start := time.Unix(0, 0)
	end, err := time.Parse("2006-01-02", "2049-12-31")
	if err != nil {
		panic(err)
	}

	serial := big.NewInt(rand.Int63())
	template := x509.Certificate{
		// TODO(elazar): instead of this ugly hack, just encode the certificate and hash the binary form.
		SerialNumber: serial,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization: []string{"GoProxy untrusted MITM proxy Inc"},
		},
		NotBefore: start,
		NotAfter:  end,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}

	hash := hashSorted(append(hosts, goproxySignerVersion, ":"+runtime.Version()))
	var csprng CounterEncryptorRand
	if csprng, err = NewCounterEncryptorRandFromKey(ca.PrivateKey, hash); err != nil {
		return
	}

	var certpriv crypto.Signer
	switch ca.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if certpriv, err = rsa.GenerateKey(&csprng, 2048); err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		if certpriv, err = ecdsa.GenerateKey(elliptic.P256(), &csprng); err != nil {
			return
		}
	default:
		err = fmt.Errorf("unsupported key type %T", ca.PrivateKey)
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(&csprng, &template, x509ca, certpriv.Public(), ca.PrivateKey); err != nil {
		return
	}
	return &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate[0]},
		PrivateKey:  certpriv,
	}, nil
}

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}
