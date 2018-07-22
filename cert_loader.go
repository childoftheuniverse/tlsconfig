package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

/*
LoadTLSCertificateAndPrivateKey loads an tls.Certificate from a private and
public key file in PEM format.
*/
func LoadTLSCertificateAndPrivateKey(
	certPath, keyPath string) ([]tls.Certificate, error) {
	var cert tls.Certificate
	var err error

	if cert, err = tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return []tls.Certificate{}, err
	}

	return []tls.Certificate{cert}, err
}

/*
LoadX509Certificate loads an X.509 certificate from a PEM encoded file.
*/
func LoadX509Certificate(certPath string) (*x509.Certificate, error) {
	var pemData []byte
	var block *pem.Block
	var err error

	if pemData, err = ioutil.ReadFile(certPath); err != nil {
		return nil, err
	}

	block, _ = pem.Decode(pemData)

	return x509.ParseCertificate(block.Bytes)
}

/*
CertPoolFromFile loads a single X.509 file and creates a CertPool from it.
*/
func CertPoolFromFile(certPath string) (*x509.CertPool, error) {
	var cert *x509.Certificate
	var pool *x509.CertPool
	var err error

	if cert, err = LoadX509Certificate(certPath); err != nil {
		return nil, err
	}

	pool = x509.NewCertPool()
	pool.AddCert(cert)

	return pool, nil
}
