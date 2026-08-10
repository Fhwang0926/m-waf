package manager

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

func loadTLSPublicKeyPin(certificatePath string) (string, error) {
	raw, err := os.ReadFile(certificatePath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("decode Manager TLS certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal Manager TLS public key: %w", err)
	}
	digest := sha256.Sum256(publicKey)
	return "sha256//" + base64.StdEncoding.EncodeToString(digest[:]), nil
}

func (s *Server) bootstrapCACertificate(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="mwaf-manager-ca.crt"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, s.ca.CertificatePEM())
}
