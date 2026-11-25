package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"time"
)

// LocalCA generates an in-memory ECDSA root CA and dynamically signs leaf certificates for MITM/loopback TLS capture.
type LocalCA struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	cache    sync.Map
}

// NewLocalCA initializes a fresh ephemeral ECDSA root CA.
func NewLocalCA() (*LocalCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	now := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "request-anything Local Diff CA",
			Organization: []string{"request-anything"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &LocalCA{rootCert: cert, rootKey: key}, nil
}

// CertForHost returns or mints a TLS certificate valid for host.
func (ca *LocalCA) CertForHost(host string) (*tls.Certificate, error) {
	if host == "" {
		host = "localhost"
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if cached, ok := ca.cache.Load(host); ok {
		return cached.(*tls.Certificate), nil
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	now := time.Now().Add(-time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now,
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host, "localhost"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.rootCert, &leafKey.PublicKey, ca.rootKey)
	if err != nil {
		return nil, err
	}
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, ca.rootCert.Raw},
		PrivateKey:  leafKey,
	}
	ca.cache.Store(host, tlsCert)
	return tlsCert, nil
}
