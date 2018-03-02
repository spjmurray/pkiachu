// Package certifcate wraps crypto/x509 into common high level abstractions
package certificate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
)

// KeyType defines the supported types of private key that can be used with
// this package.
type KeyType int

// RSA and all supported ECDSA curves may be specified.
const (
	KeyTypeRSA KeyType = iota
	KeyTypeECDSAP224
	KeyTypeECDSAP256
	KeyTypeECDSAP384
	KeyTypeECDSAP521
)

// ReadCertificateChain reads a file from disk and iteratively parses out
// certificates.
func ReadCertificateChain(path string) ([]*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{}
	for len(data) != 0 {
		pem, rest := pem.Decode(data)
		if pem == nil {
			return nil, fmt.Errorf("unable to parse PEM certificate")
		}
		if pem.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("non CERTIFICATE PEM type in file")
		}
		cert, err := x509.ParseCertificate(pem.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		data = rest
	}

	return certs, nil
}

// ReadCertificate is a wrapper around ReadCertificateChain which expects
// only a single certificate to be present in the specified file.
func ReadCertificate(path string) (*x509.Certificate, error) {
	certs, err := ReadCertificateChain(path)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("certificate chain found")
	}
	return certs[0], nil
}

// ReadPrivateKey reads a private key from a file on disk.  All formats
// supoprted by go are supported here.
func ReadPrivateKey(path string, password []byte) (crypto.PrivateKey, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pem, rest := pem.Decode(data)
	if pem == nil {
		return nil, fmt.Errorf("unable to parse PEM private key")
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("extra data encountered while parsing private key")
	}
	if !strings.HasSuffix(pem.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("unexpected PEM type: %v", pem.Type)
	}

	// RFC 1421
	bytes := pem.Bytes
	if field, ok := pem.Headers["Proc-Type"]; ok {
		subfields := strings.Split(field, ",")
		if len(subfields) != 2 {
			return nil, fmt.Errorf("malformed Proc-Type header")
		}
		if subfields[1] == "ENCRYPTED" {
			bytes, err = x509.DecryptPEMBlock(pem, password)
		}
	}

	if key, err := x509.ParseECPrivateKey(bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unable to parse private key")
}

// GeneratePrivateKey generates a private key as defined by KeyType.
func GeneratePrivateKey(keyType KeyType) (crypto.PrivateKey, error) {
	var key crypto.PrivateKey
	var err error
	switch keyType {
	case KeyTypeRSA:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeECDSAP224:
		key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case KeyTypeECDSAP256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECDSAP384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeECDSAP521:
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

// CreatePrivateKeyPEM takes a private key input and returns it as a PEM
// encoded slice
func CreatePrivateKey(key crypto.PrivateKey) ([]byte, error) {
	var block *pem.Block
	switch t := key.(type) {
	case *rsa.PrivateKey:
		block = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(t),
		}
	case *ecdsa.PrivateKey:
		bytes, err := x509.MarshalECPrivateKey(t)
		if err != nil {
			return nil, err
		}
		block = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: bytes,
		}
	default:
		info := reflect.TypeOf(t)
		return nil, fmt.Errorf("unsupported key type %v", info.Name())
	}

	data := &bytes.Buffer{}
	if err := pem.Encode(data, block); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func CreateCertificate(cert []byte) ([]byte, error) {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	data := &bytes.Buffer{}
	if err := pem.Encode(data, block); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func CreateCertificateRequest(req *x509.CertificateRequest, key crypto.PrivateKey) ([]byte, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	data := &bytes.Buffer{}
	if err := pem.Encode(data, block); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

func ParseCertificateRequest(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)

	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}

	return req, nil
}
