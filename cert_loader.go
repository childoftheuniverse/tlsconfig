package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"

	"github.com/prometheus/client_golang/prometheus"
)

var certValidityStartTimes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "tlsconfig",
	Subsystem: "cert_loader",
	Name:      "cert_validity_start_times",
	Help:      "Timestamps in UNIX seconds of when the certificate became valid",
}, []string{"subject", "serial"})
var certValidityEndTimes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "tlsconfig",
	Subsystem: "cert_loader",
	Name:      "cert_validity_end_times",
	Help:      "Timestamps in UNIX seconds of when the certificate expires",
}, []string{"subject", "serial"})

func init() {
	prometheus.MustRegister(certValidityStartTimes)
	prometheus.MustRegister(certValidityEndTimes)
}

/*
LoadTLSCertificateAndPrivateKey loads an tls.Certificate from a private and
public key file in PEM format.
*/
func LoadTLSCertificateAndPrivateKey(
	certPath, keyPath string) ([]tls.Certificate, error) {
	var certs = make([]tls.Certificate, 0)
	var block *pem.Block
	var certBytes []byte
	var keyBytes []byte
	var cert tls.Certificate
	var x509cert *x509.Certificate
	var err error

	if keyBytes, err = ioutil.ReadFile(keyPath); err != nil {
		return []tls.Certificate{}, err
	}
	if certBytes, err = ioutil.ReadFile(certPath); err != nil {
		return []tls.Certificate{}, err
	}

	for len(keyBytes) > 0 && len(certBytes) > 0 {
		var keyRemainder, certRemainder []byte

		_, keyRemainder = pem.Decode(keyBytes)
		block, certRemainder = pem.Decode(certBytes)

		if x509cert, err = x509.ParseCertificate(block.Bytes); err != nil {
			return []tls.Certificate{}, err
		}

		certValidityStartTimes.With(prometheus.Labels{
			"subject": x509cert.Subject.String(),
			"serial":  x509cert.SerialNumber.String(),
		}).Set(float64(x509cert.NotBefore.Unix()))
		certValidityEndTimes.With(prometheus.Labels{
			"subject": x509cert.Subject.String(),
			"serial":  x509cert.SerialNumber.String(),
		}).Set(float64(x509cert.NotAfter.Unix()))

		if cert, err = tls.X509KeyPair(certBytes, keyBytes); err != nil {
			return []tls.Certificate{}, err
		}
		if cert.Leaf == nil {
			cert.Leaf = x509cert
		}

		keyBytes = keyRemainder
		certBytes = certRemainder
		certs = append(certs, cert)
	}

	return certs, err
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

		certValidityStartTimes.With(prometheus.Labels{
			"subject": cert.Subject.String(),
			"serial":  cert.SerialNumber.String(),
		}).Set(float64(cert.NotBefore.Unix()))
		certValidityEndTimes.With(prometheus.Labels{
			"subject": cert.Subject.String(),
			"serial":  cert.SerialNumber.String(),
		}).Set(float64(cert.NotAfter.Unix()))

		certs = append(certs, cert)
		pemData = remainder
	}

	return certs, err
}

/*
LoadX509Certificate loads an X.509 certificate from a PEM encoded file.
*/
func LoadX509Certificate(certPath string) (*x509.Certificate, error) {
	var cert *x509.Certificate
	var pemData []byte
	var block *pem.Block
	var err error

	if pemData, err = ioutil.ReadFile(certPath); err != nil {
		return nil, err
	}

	block, _ = pem.Decode(pemData)

	if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return nil, err
	}
	certValidityStartTimes.With(prometheus.Labels{
		"subject": cert.Subject.String(),
		"serial":  cert.SerialNumber.String(),
	}).Set(float64(cert.NotBefore.Unix()))
	certValidityEndTimes.With(prometheus.Labels{
		"subject": cert.Subject.String(),
		"serial":  cert.SerialNumber.String(),
	}).Set(float64(cert.NotAfter.Unix()))
	return cert, nil
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
