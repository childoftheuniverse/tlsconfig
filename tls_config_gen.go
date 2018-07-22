package tlsconfig

import (
	"crypto/tls"
)

/*
TLSConfigWithRootCA creates a TLS config with only the root CA filled in.
*/
func TLSConfigWithRootCA(rootCaPath string) (*tls.Config, error) {
	var config = new(tls.Config)
	var err error

	/*
	   Some reasonably secure defaults as recommended on http://cipherli.st/
	*/
	config.MinVersion = tls.VersionTLS12
	config.CurvePreferences = []tls.CurveID{
		tls.CurveP521, tls.CurveP384, tls.CurveP256}
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}

	config.RootCAs, err = CertPoolFromFile(rootCaPath)
	return config, err
}

/*
TLSConfigWithRootCAAndCert creates a TLS config with the root CA filled in
as well as a TLS certificate to authenticate to peers with.
*/
func TLSConfigWithRootCAAndCert(
	rootCaPath, certPath, keyPath string) (*tls.Config, error) {
	var config *tls.Config
	var err error

	if config, err = TLSConfigWithRootCA(rootCaPath); err != nil {
		return nil, err
	}

	config.Certificates, err = LoadTLSCertificateAndPrivateKey(
		certPath, keyPath)
	return config, err
}

/*
TLSConfigWithRootAndClientCA creates a TLS config with the root and client
CAs filled in.
*/
func TLSConfigWithRootAndClientCA(
	rootCaPath, clientCaPath string) (*tls.Config, error) {
	var config *tls.Config
	var err error

	if config, err = TLSConfigWithRootCA(rootCaPath); err != nil {
		return nil, err
	}

	/*
	   Since we're setting up a client CA, init the ClientAuth value with
	   something useful.
	*/
	config.ClientAuth = tls.VerifyClientCertIfGiven

	config.ClientCAs, err = CertPoolFromFile(clientCaPath)
	return config, err
}

/*
TLSConfigWithRootAndClientCAAndCert creates a TLS config with the root and
client CAs filled in as well as a TLS certificate to authenticate to peers with.
*/
func TLSConfigWithRootAndClientCAAndCert(
	rootCaPath, clientCaPath, certPath, keyPath string) (*tls.Config, error) {
	var config *tls.Config
	var err error

	if config, err = TLSConfigWithRootAndClientCA(
		rootCaPath, clientCaPath); err != nil {
		return nil, err
	}

	config.Certificates, err = LoadTLSCertificateAndPrivateKey(
		certPath, keyPath)
	return config, err
}
