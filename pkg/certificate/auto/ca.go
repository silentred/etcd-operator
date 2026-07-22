// Package auto provides an in-cluster certificate authority used by the etcd
// operator's auto certificate provider. The same CA signs every leaf
// certificate the provider issues for one EtcdCluster.
package auto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// CA Secret data keys. The CA Secret is an Opaque Secret and never carries
// leaf private keys; those remain in each leaf Secret's "tls.key".
const (
	caCertKey = "ca.crt"
	caKeyKey  = "ca.key"
)

// caCommonName is the Subject.CommonName placed on the generated CA
// certificate. It identifies the operator's auto-provider CA in logs and
// external tooling; cluster scope is conveyed by the Secret namespace/name.
const caCommonName = "etcd-operator-auto-ca"

// generateCA creates a new ECDSA P-521 self-signed CA certificate and returns
// its PEM-encoded certificate and private key. The certificate has IsCA=true,
// the appropriate basic constraints and key usage, and the requested validity
// window. The serial number is a cryptographically random 128-bit value.
func generateCA(validity time.Duration) (certPEM, keyPEM []byte, err error) {
	if validity <= 0 {
		return nil, nil, fmt.Errorf("CA validity must be positive, got %v", validity)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA serial: %w", err)
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   caCommonName,
			Organization: []string{"etcd-operator"},
		},
		NotBefore: now,
		NotAfter:  now.Add(validity),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA private key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// parseCASecret validates the Opaque Secret data and returns the parsed CA
// certificate and private key. It enforces that both data keys are present,
// the PEM is well formed, the certificate is a CA, the certificate is within
// its validity window, and the private key matches the certificate's public
// key. parseCASecret never returns a partially-parsed certificate when the
// key check fails.
func parseCASecret(secret *corev1.Secret) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return parseCASecretData(secret.Name, secret.Data[caCertKey], secret.Data[caKeyKey])
}

// parseCASecretData is the testable form of parseCASecret, used by both the
// provider and its unit tests.
func parseCASecretData(name string, certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if len(certPEM) == 0 {
		return nil, nil, fmt.Errorf("CA secret %s missing %s", name, caCertKey)
	}
	if len(keyPEM) == 0 {
		return nil, nil, fmt.Errorf("CA secret %s missing %s", name, caKeyKey)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("CA secret %s: %s is not valid PEM", name, caCertKey)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CA secret %s: parse %s: %w", name, caCertKey, err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("CA secret %s: %s is not valid PEM", name, caKeyKey)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CA secret %s: parse %s: %w", name, caKeyKey, err)
	}

	if !cert.IsCA {
		return nil, nil, fmt.Errorf("CA secret %s: %s is not a CA certificate", name, caCertKey)
	}

	now := time.Now()
	if cert.NotBefore.After(now) {
		return nil, nil, fmt.Errorf("CA secret %s: %s is not yet valid", name, caCertKey)
	}
	if cert.NotAfter.Before(now) {
		return nil, nil, fmt.Errorf("CA secret %s: %s is expired", name, caCertKey)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("CA secret %s: %s public key is not ECDSA", name, caCertKey)
	}
	if !pub.Equal(&key.PublicKey) {
		return nil, nil, fmt.Errorf("CA secret %s: %s does not match %s", name, caKeyKey, caCertKey)
	}

	return cert, key, nil
}
