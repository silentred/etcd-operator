package auto

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	interfaces "go.etcd.io/etcd-operator/pkg/certificate/interfaces"
)

type Provider struct {
	client.Client
	config *interfaces.Config
}

var _ interfaces.Provider = (*Provider)(nil)

func New(c client.Client) interfaces.Provider {
	return &Provider{
		Client: c,
		config: nil,
	}
}

// EnsureCASecret creates the operator-managed signing CA Secret for the
// cluster if it does not exist. An existing Secret is validated and never
// replaced. Two reconcilers racing to create the same Secret both succeed:
// the loser observes the winner's Secret and validates it.
func (ac *Provider) EnsureCASecret(ctx context.Context, secretKey client.ObjectKey, validity time.Duration) error {
	if secretKey.Name == "" || secretKey.Namespace == "" {
		return fmt.Errorf("CA secret key requires both name and namespace, got %+v", secretKey)
	}

	existing := &corev1.Secret{}
	getErr := ac.Get(ctx, secretKey, existing)
	if getErr == nil {
		return validateCAReferenceSecret(secretKey.Name, existing)
	}
	if !k8serrors.IsNotFound(getErr) {
		return fmt.Errorf("failed to fetch CA secret %s/%s: %w", secretKey.Namespace, secretKey.Name, getErr)
	}

	certPEM, keyPEM, err := generateCA(validity)
	if err != nil {
		return fmt.Errorf("failed to generate CA for %s/%s: %w", secretKey.Namespace, secretKey.Name, err)
	}

	newSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretKey.Name,
			Namespace: secretKey.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caCertKey: certPEM,
			caKeyKey:  keyPEM,
		},
	}

	if createErr := ac.Create(ctx, newSecret); createErr != nil {
		if k8serrors.IsAlreadyExists(createErr) {
			// Another reconciler won the race. Validate the winner rather than
			// generating a competing CA.
			raced := &corev1.Secret{}
			if getRacedErr := ac.Get(ctx, secretKey, raced); getRacedErr != nil {
				return fmt.Errorf("CA secret %s/%s: %w", secretKey.Namespace, secretKey.Name, getRacedErr)
			}
			return validateCAReferenceSecret(secretKey.Name, raced)
		}
		return fmt.Errorf("failed to create CA secret %s/%s: %w", secretKey.Namespace, secretKey.Name, createErr)
	}
	return nil
}

// validateCAReferenceSecret enforces the invariants the controller relies on:
// the Secret data carries a CA certificate and a matching private key that
// is currently valid. The existing data is never modified.
func validateCAReferenceSecret(name string, secret *corev1.Secret) error {
	if secret.Type != corev1.SecretTypeOpaque {
		return fmt.Errorf("CA secret %s must be of type Opaque, got %s", name, secret.Type)
	}
	if _, _, err := parseCASecret(secret); err != nil {
		return err
	}
	return nil
}

func (ac *Provider) EnsureCertificateSecret(ctx context.Context, secretKey client.ObjectKey,
	cfg *interfaces.Config) error {
	// Save the user-defined Config so GetCertificateConfig can return it later.
	ac.config = cfg

	if cfg == nil {
		return fmt.Errorf("auto provider requires a non-nil Config")
	}
	if cfg.Role == "" {
		return fmt.Errorf("auto provider requires a non-empty Role in Config")
	}
	if cfg.SigningCASecret == "" {
		return fmt.Errorf("auto provider requires a non-empty SigningCASecret in Config")
	}

	caCert, caPriv, err := ac.loadSharedCA(ctx, secretKey.Namespace, cfg.SigningCASecret)
	if err != nil {
		return err
	}

	existing := &corev1.Secret{}
	getErr := ac.Get(ctx, secretKey, existing)
	if getErr == nil {
		return validateLeafSecret(secretKey.Name, existing, caCert, cfg.Role)
	}
	if !k8serrors.IsNotFound(getErr) {
		return fmt.Errorf("failed to fetch leaf secret %s/%s: %w", secretKey.Namespace, secretKey.Name, getErr)
	}

	return ac.createNewLeafSecret(ctx, secretKey, cfg, caCert, caPriv)
}

// loadSharedCA fetches the cluster's signing CA Secret and returns the parsed
// CA certificate and private key. The auto provider requires this Secret to
// be present before any leaf can be ensured.
func (ac *Provider) loadSharedCA(ctx context.Context, namespace, caName string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caSecret := &corev1.Secret{}
	if err := ac.Get(ctx, client.ObjectKey{Name: caName, Namespace: namespace}, caSecret); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil, nil, fmt.Errorf("shared CA secret %s/%s not found; controller must ensure the CA before leaves", namespace, caName)
		}
		return nil, nil, fmt.Errorf("failed to fetch shared CA secret %s/%s: %w", namespace, caName, err)
	}
	if caSecret.Type != corev1.SecretTypeOpaque {
		return nil, nil, fmt.Errorf("shared CA secret %s/%s must be of type Opaque, got %s", namespace, caName, caSecret.Type)
	}
	caCert, caPriv, err := parseCASecret(caSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("shared CA secret %s/%s invalid: %w", namespace, caName, err)
	}
	return caCert, caPriv, nil
}

// createNewLeafSecret signs a new leaf certificate with the supplied shared
// CA and writes the kubernetes.io/tls Secret data. If two reconcilers race
// to create the same Secret, the loser validates the winner's Secret.
func (ac *Provider) createNewLeafSecret(ctx context.Context, secretKey client.ObjectKey, cfg *interfaces.Config, caCert *x509.Certificate, caPriv *ecdsa.PrivateKey) error {
	leaf, leafKey, err := createLeafCert(caCert, caPriv, cfg)
	if err != nil {
		return fmt.Errorf("create leaf certificate for %s/%s: %w", secretKey.Namespace, secretKey.Name, err)
	}
	certPEM, keyPEM, err := encodeLeafPEM(leaf, leafKey)
	if err != nil {
		return fmt.Errorf("encode leaf PEM for %s/%s: %w", secretKey.Namespace, secretKey.Name, err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretKey.Name,
			Namespace: secretKey.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			leafCertKey:  certPEM,
			leafKeyKey:   keyPEM,
			leafCABundle: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}),
		},
	}

	if createErr := ac.Create(ctx, secret); createErr != nil {
		if k8serrors.IsAlreadyExists(createErr) {
			// Race: another reconciler won. Validate the winner rather than
			// signing a competing leaf.
			winner := &corev1.Secret{}
			if getErr := ac.Get(ctx, secretKey, winner); getErr != nil {
				return fmt.Errorf("leaf secret %s/%s: %w", secretKey.Namespace, secretKey.Name, getErr)
			}
			return validateLeafSecret(secretKey.Name, winner, caCert, cfg.Role)
		}
		return fmt.Errorf("failed to create leaf secret %s/%s: %w", secretKey.Namespace, secretKey.Name, createErr)
	}
	return nil
}

func (ac *Provider) ValidateCertificateSecret(ctx context.Context, secretKey client.ObjectKey,
	cfg *interfaces.Config) error {
	if cfg == nil || cfg.SigningCASecret == "" {
		return fmt.Errorf("ValidateCertificateSecret requires a Config with SigningCASecret")
	}
	caCert, _, err := ac.loadSharedCA(ctx, secretKey.Namespace, cfg.SigningCASecret)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{}
	if err := ac.Get(ctx, secretKey, secret); err != nil {
		return err
	}
	return validateLeafSecret(secretKey.Name, secret, caCert, cfg.Role)
}

func (ac *Provider) DeleteCertificateSecret(ctx context.Context, secretKey client.ObjectKey) error {
	var secret corev1.Secret
	if err := ac.Get(ctx, secretKey, &secret); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return err
	}
	return ac.Delete(ctx, &secret)
}

func (ac *Provider) RevokeCertificate(ctx context.Context, secretKey client.ObjectKey) error {
	return ac.DeleteCertificateSecret(ctx, secretKey)
}

func (ac *Provider) GetCertificateConfig(ctx context.Context,
	secretKey client.ObjectKey) (*interfaces.Config, error) {
	var autoCertSecret corev1.Secret
	err := ac.Get(ctx, secretKey, &autoCertSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	// If config was set during creation, return it
	if ac.config != nil {
		return ac.config, nil
	}

	// For existing secrets, parse the certificate to extract the config
	cert, err := parseCertificateFromSecret(&autoCertSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from secret: %w", err)
	}

	// Extract config from the certificate
	config := &interfaces.Config{
		CommonName:   cert.Subject.CommonName,
		Organization: cert.Subject.Organization,
		AltNames: interfaces.AltNames{
			DNSNames: cert.DNSNames,
			IPs:      cert.IPAddresses,
		},
	}

	return config, nil
}

// parseCertificateFromSecret extracts and parses the x509 certificate from a Kubernetes secret.
func parseCertificateFromSecret(secret *corev1.Secret) (*x509.Certificate, error) {
	certData, ok := secret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, interfaces.ErrTLSCert
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, interfaces.ErrDecodeCert
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}
