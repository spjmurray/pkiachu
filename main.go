package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"certificate"
	"certificate/authority"
	"server"
)

const (
	CACert        = "ca/pki/ca.crt"
	CAKey         = "ca/pki/private/ca.key"
	CAKeyPassword = "password"
)

func csrTest() error {
	key, err := certificate.GeneratePrivateKey(certificate.KeyTypeRSA)
	if err != nil {
		return err
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "host.domain.com",
		},
		DNSNames: []string{
			"host.domain.com",
		},
	}

	pem, err := certificate.CreateCertificateRequest(req, key)
	if err != nil {
		return err
	}

	ca, err := authority.NewCertificateAuthority(CACert, CAKey, []byte(CAKeyPassword))
	if err != nil {
		return err
	}
	cert, err := ca.SignCertificateRequest(pem, authority.CertTypeServer)
	if err != nil {
		return err
	}

	if keyPem, err := certificate.CreatePrivateKey(key); err != nil {
		return err
	} else {
		fmt.Print(string(keyPem))
	}

	fmt.Print(string(cert))

	return nil
}

func serve() error {
	key, err := certificate.GeneratePrivateKey(certificate.KeyTypeRSA)
	if err != nil {
		return err
	}

	keyPEM, err := certificate.CreatePrivateKey(key)
	if err != nil {
		return err
	}

	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "host.domain.com",
		},
		DNSNames: []string{
			"host.domain.com",
		},
	}

	reqPEM, err := certificate.CreateCertificateRequest(req, key)
	if err != nil {
		return err
	}

	ca, err := authority.NewCertificateAuthority(CACert, CAKey, []byte(CAKeyPassword))
	if err != nil {
		return err
	}
	cert, err := ca.SignCertificateRequest(reqPEM, authority.CertTypeServer)
	if err != nil {
		return err
	}

	s := &server.Server{
		Certificate: cert,
		Key:         keyPEM,
		BindPort:    1443,
	}
	if err := s.Run(); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := csrTest(); err != nil {
		fmt.Println(err.Error())
		return
	}
	/*if err := serve(); err != nil {
		fmt.Println(err.Error())
	}*/
}
