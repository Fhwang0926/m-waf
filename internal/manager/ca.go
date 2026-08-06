package manager

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

type CertificateAuthority struct {
	certificate    *x509.Certificate
	privateKey     crypto.Signer
	certificatePEM string
}

func LoadCertificateAuthority(certificatePath, privateKeyPath string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("read agent CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read agent CA private key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("decode agent CA certificate")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("decode agent CA private key")
	}
	privateKey, err := parseSigner(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CertificateAuthority{certificate: certificate, privateKey: privateKey, certificatePEM: string(certPEM)}, nil
}

func (c *CertificateAuthority) CertificatePEM() string { return c.certificatePEM }

func (c *CertificateAuthority) SignAgentCSR(csrPEM, serverID string) (string, string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", "", errors.New("invalid certificate request PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", "", err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", err
	}
	spiffe, _ := url.Parse("spiffe://mwaf/agent/" + serverID)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"M-WAF"},
			CommonName:   serverID,
		},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{spiffe},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.certificate, csr.PublicKey, c.privateKey)
	if err != nil {
		return "", "", err
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return string(encoded), hex.EncodeToString(serial.Bytes()), nil
}

func parseSigner(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported agent CA private key")
}
