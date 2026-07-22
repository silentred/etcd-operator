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
	"net"
	"time"

	corev1 "k8s.io/api/core/v1"

	interfaces "go.etcd.io/etcd-operator/pkg/certificate/interfaces"
)

// Leaf Secret data keys. Leaf Secrets remain kubernetes.io/tls so etcd can
// mount them at the same paths the existing TLS arg builder expects.
const (
	leafCertKey   = "tls.crt"
	leafKeyKey    = "tls.key"
	leafCABundle  = "ca.crt"
)

// extKeyUsageForRole returns the Extended Key Usage set a leaf certificate
// must carry for the given certificate role. Peer certificates need both
// usages because the etcd peer listener accepts mutual TLS connections in
// either direction.
func extKeyUsageForRole(role interfaces.CertificateRole) []x509.ExtKeyUsage {
	switch role {
	case interfaces.CertificateRoleClient:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case interfaces.CertificateRoleServer:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case interfaces.CertificateRolePeer:
		return []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	return nil
}

// createLeafCert signs a new leaf certificate using the supplied CA. It
// returns the parsed leaf certificate and its matching private key. The leaf
// is a non-CA ECDSA P-521 certificate with the role-appropriate Extended Key
// Usage set. The caller is responsible for serialising the result into a
// Secret.
func createLeafCert(ca *x509.Certificate, caKey *ecdsa.PrivateKey, cfg *interfaces.Config) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if ca == nil {
		return nil, nil, fmt.Errorf("leaf signing requires a CA certificate")
	}
	if caKey == nil {
		return nil, nil, fmt.Errorf("leaf signing requires a CA private key")
	}
	if cfg == nil {
		return nil, nil, fmt.Errorf("leaf signing requires a non-nil Config")
	}
	if cfg.ValidityDuration <= 0 {
		return nil, nil, fmt.Errorf("leaf validity must be positive, got %v", cfg.ValidityDuration)
	}
	if !ca.NotAfter.IsZero() && !ca.NotBefore.IsZero() {
		// CA must cover the entire requested leaf validity window. Compare
		// against the CA's original validity window so that a CA and a leaf
		// requested with the same duration succeed regardless of the small
		// amount of time elapsed between CA creation and leaf signing.
		caValidity := ca.NotAfter.Sub(ca.NotBefore)
		if cfg.ValidityDuration > caValidity {
			return nil, nil, fmt.Errorf("CA validity %s is shorter than the requested leaf validity %s",
				caValidity, cfg.ValidityDuration)
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf serial: %w", err)
	}

	subject := pkix.Name{CommonName: cfg.CommonName}
	if len(cfg.Organization) > 0 {
		subject.Organization = append([]string(nil), cfg.Organization...)
	}

	ekus := extKeyUsageForRole(cfg.Role)
	if len(ekus) == 0 {
		return nil, nil, fmt.Errorf("leaf certificate requires a known role, got %q", cfg.Role)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now,
		NotAfter:     now.Add(cfg.ValidityDuration),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           ekus,
		BasicConstraintsValid: true,
		IsCA:                  false,

		DNSNames:    append([]string(nil), cfg.AltNames.DNSNames...),
		IPAddresses: append([]net.IP(nil), cfg.AltNames.IPs...),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signed leaf certificate: %w", err)
	}
	return cert, priv, nil
}

// encodeLeafPEM returns the PEM encoding of a leaf certificate and its
// matching private key in a form suitable for the kubernetes.io/tls Secret
// contract (tls.crt / tls.key).
func encodeLeafPEM(cert *x509.Certificate, key *ecdsa.PrivateKey) (certPEM, keyPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// validateLeafSecret enforces that the supplied Secret is a kubernetes.io/tls
// Secret whose tls.crt is signed by the supplied shared CA, whose tls.key
// matches tls.crt, and whose role-appropriate Extended Key Usage set is
// present. The existing data is never modified.
func validateLeafSecret(name string, secret *corev1.Secret, ca *x509.Certificate, role interfaces.CertificateRole) error {
	if secret.Type != corev1.SecretTypeTLS {
		return fmt.Errorf("leaf secret %s must be of type kubernetes.io/tls, got %s", name, secret.Type)
	}
	if _, ok := secret.Data[leafCertKey]; !ok {
		return fmt.Errorf("leaf secret %s missing %s", name, leafCertKey)
	}
	if _, ok := secret.Data[leafKeyKey]; !ok {
		return fmt.Errorf("leaf secret %s missing %s", name, leafKeyKey)
	}
	if len(secret.Data[leafCABundle]) == 0 {
		return fmt.Errorf("leaf secret %s missing %s", name, leafCABundle)
	}

	certBlock, _ := pem.Decode(secret.Data[leafCertKey])
	if certBlock == nil {
		return fmt.Errorf("leaf secret %s: %s is not valid PEM", name, leafCertKey)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("leaf secret %s: parse %s: %w", name, leafCertKey, err)
	}

	keyBlock, _ := pem.Decode(secret.Data[leafKeyKey])
	if keyBlock == nil {
		return fmt.Errorf("leaf secret %s: %s is not valid PEM", name, leafKeyKey)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("leaf secret %s: parse %s: %w", name, leafKeyKey, err)
	}

	if cert.IsCA {
		return fmt.Errorf("leaf secret %s: %s must not be a CA certificate", name, leafCertKey)
	}

	now := time.Now()
	if cert.NotBefore.After(now) {
		return fmt.Errorf("leaf secret %s: %s is not yet valid", name, leafCertKey)
	}
	if cert.NotAfter.Before(now) {
		return fmt.Errorf("leaf secret %s: %s is expired", name, leafCertKey)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("leaf secret %s: %s public key is not ECDSA", name, leafCertKey)
	}
	if !pub.Equal(&key.PublicKey) {
		return fmt.Errorf("leaf secret %s: %s does not match %s", name, leafKeyKey, leafCertKey)
	}

	// Reject leafs that were not signed by the supplied shared CA. Use
	// x509.Verify with a CertPool so any later revocation/chain work can
	// extend this check.
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: extKeyUsageForRole(role),
	}); err != nil {
		return fmt.Errorf("leaf secret %s: certificate is not signed by the shared CA: %w", name, err)
	}

	// Confirm the leaf Secret carries the shared CA in ca.crt so etcd and the
	// operator can trust the chain without separately fetching the CA Secret.
	caBlock, _ := pem.Decode(secret.Data[leafCABundle])
	if caBlock == nil {
		return fmt.Errorf("leaf secret %s: %s is not valid PEM", name, leafCABundle)
	}
	bundleCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("leaf secret %s: parse %s: %w", name, leafCABundle, err)
	}
	if !bundleCert.Equal(ca) {
		return fmt.Errorf("leaf secret %s: %s does not match the shared CA certificate", name, leafCABundle)
	}

	return nil
}