package manager

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

type PolicySigner struct {
	privateKey ed25519.PrivateKey
	publicPEM  string
}

func LoadPolicySigner(privatePath, publicPath string) (*PolicySigner, error) {
	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		return nil, fmt.Errorf("read policy signing key: %w", err)
	}
	block, _ := pem.Decode(privatePEM)
	if block == nil {
		return nil, errors.New("decode policy signing private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse policy signing private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("policy signing key must be Ed25519")
	}
	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("read policy signing public key: %w", err)
	}
	publicBlock, _ := pem.Decode(publicPEM)
	if publicBlock == nil {
		return nil, errors.New("decode policy signing public key")
	}
	publicParsed, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse policy signing public key: %w", err)
	}
	publicKey, ok := publicParsed.(ed25519.PublicKey)
	if !ok || !publicKey.Equal(privateKey.Public()) {
		return nil, errors.New("policy signing public/private key mismatch")
	}
	return &PolicySigner{privateKey: privateKey, publicPEM: string(publicPEM)}, nil
}

func (s *PolicySigner) Sign(raw []byte) (string, string) {
	hash := sha256.Sum256(raw)
	signature := ed25519.Sign(s.privateKey, raw)
	return hex.EncodeToString(hash[:]), base64.StdEncoding.EncodeToString(signature)
}

func (s *PolicySigner) Verify(raw []byte, encoded string) bool {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && ed25519.Verify(s.privateKey.Public().(ed25519.PublicKey), raw, signature)
}

func (s *PolicySigner) PublicPEM() string { return s.publicPEM }
