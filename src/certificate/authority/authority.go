// Package authority acts as a CA signing and revoking x509 certificates
package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"certificate"
)

// CertType defines the type of certificate generated when a certificate
// request is signed.
type CertType int

// When the type is CertTypeServer the certificate will allow use as a
// server certificate and allow digital signatures and encryption of keying
// material.
// When the type is CertTypeClient the certificate will allow use as a
// client certificate and allow digital signatures only.
const (
	CertTypeServer CertType = iota
	CertTypeClient
)

// CertificateAuthority contains all necessary information to digitally
// sign certificates
type CertifcateAuthority struct {
	Certificate *x509.Certificate
	Key         crypto.PrivateKey
}

// NewCertificateAuthority creates a new certificate authority.  The
// cert and key parameters are paths to the CA certificate and key on
// disk.  The password parameter is optional and is only valid if the
// private key is encrypted with password protection.
func NewCertificateAuthority(cert, key string, password []byte) (*CertifcateAuthority, error) {
	caCert, err := certificate.ReadCertificate(cert)
	if err != nil {
		return nil, err
	}
	caKey, err := certificate.ReadPrivateKey(key, password)
	if err != nil {
		return nil, err
	}
	ca := &CertifcateAuthority{
		Certificate: caCert,
		Key:         caKey,
	}
	return ca, nil
}

// generateSerial creates a unique certificate serial number as defined
// in RFC 3280.  It is upto 20 octets in length and non-negative
func generateSerial() (*big.Int, error) {
	// 16 octects seems to be the defacto standard
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	return serialNumber, nil
}

// SignCertificateRequest accepts a certificate request data structure
// validates it has been signed by the private key associated with the
// request's public key and authenticates the certificate by the CA.
// The certType defines the key usage and extended key usage defined
// by the CertType.
// The returned slice is the PEM encoded certificate.
func (ca *CertifcateAuthority) SignCertificateRequest(request []byte, certType CertType) ([]byte, error) {
	// Load the PEM file into a CertificateRequest
	req, err := certificate.ParseCertificateRequest(request)
	if err != nil {
		return nil, err
	}

	// Check the CSR was signed by the private key of the certificate
	if err := req.CheckSignature(); err != nil {
		return nil, err
	}

	// TODO: Need to keep an index and verify uniqueness
	serialNumber, err := generateSerial()
	if err != nil {
		return nil, err
	}

	// TODO: Duration should be configurable
	notBefore := time.Now()
	notAfter := notBefore.AddDate(10, 0, 0)

	cert := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               req.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
	}

	switch certType {
	case CertTypeServer:
		cert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case CertTypeClient:
		cert.KeyUsage = x509.KeyUsageDigitalSignature
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		return nil, fmt.Errorf("invalid certificate type")
	}

	data, err := x509.CreateCertificate(rand.Reader, cert, ca.Certificate, req.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}

	pem, err := certificate.CreateCertificate(data)
	if err != nil {
		return nil, err
	}

	return pem, nil
}
