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
LoadX509Certificates loads a list of X.509 certificates from a PEM encoded
file.
*/
func LoadX509Certificates(certPath string) ([]*x509.Certificate, error) {
	var pemData []byte
	var block *pem.Block
	var remainder []byte
	var certs []*x509.Certificate = make([]*x509.Certificate, 0)
	var err error

	if pemData, err = ioutil.ReadFile(certPath); err != nil {
		return nil, err
	}

	for len(pemData) > 0 {
		var cert *x509.Certificate
		block, remainder = pem.Decode(pemData)

		if len(pemData) == len(remainder) {
			break
		}

		if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
			return certs, err
		}

		certs = append(certs, cert)
		pemData = remainder
	}

	return certs, err
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
	var certs []*x509.Certificate
	var cert *x509.Certificate
	var pool *x509.CertPool
	var err error

	if certs, err = LoadX509Certificates(certPath); err != nil {
		return nil, err
	}

	pool = x509.NewCertPool()

	for _, cert = range certs {
		pool.AddCert(cert)
	}

	return pool, nil
}
