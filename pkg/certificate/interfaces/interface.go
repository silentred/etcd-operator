package certificate

import (
	"context"
	"errors"
	"net"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrPending is returned when the Certificate is not in "Ready" state
	ErrPending = errors.New("certificate creation pending")

	// ErrUnknown is returned when the Certificate status does not match the provider defined states
	ErrUnknown = errors.New("certificate status unknown")

	// ErrTLSKey is returned when private key not found in Certificate secret
	ErrTLSKey = errors.New("private key not found in secret")

	// ErrTLSCert is returned when private key certificate not found in Certificate secret
	ErrTLSCert = errors.New("certificate not found in secret")

	// ErrDecodeCert is returned when failed to decode PEM block of tls.crt of Certificate secret
	ErrDecodeCert = errors.New("failed to decode PEM block")

	// ErrCertExpired is returned when certificate has expired
	ErrCertExpired = errors.New("certificate has expired")

	// ErrCertNotYetValid is returned when certificate is not yet valid
	ErrCertNotYetValid = errors.New("certificate is not yet valid")

	// ErrRSAKeyPair is returned when private key(RSA) does not match the public key in the Certificate secret
	ErrRSAKeyPair = errors.New("private key(RSA) does not match the public key in the certificate")

	// ErrECDSAKeyPair is returned when private key(ECDSA) does not match the public key in the Certificate secret
	ErrECDSAKeyPair = errors.New("private key(ECDSA) does not match the public key in the certificate")

	// ErrED25519KeyPair is returned when private key(ED25519) does not match the public key in the Certificate secret
	ErrED25519KeyPair = errors.New("private key(ED25519) does not match the public key in the certificate")
)

const (
	// MaxRetries is the maximum number of retry attempts for EnsureCertificateSecret, ValidateCertificateSecret
	// with a delay of RetryInterval between consecutive retries
	MaxRetries    = 36
	RetryInterval = 5 * time.Second

	// DefaultAutoValidity is the default validity duration for auto-generated certificates (365 days)
	DefaultAutoValidity = 365 * 24 * time.Hour

	// DefaultCertManagerValidity is the default validity duration for cert-manager certificates (90 days)
	DefaultCertManagerValidity = 90 * 24 * time.Hour

	// DefaultDomainName is the default domain name for creating certificates
	DefaultDomainName = "svc.cluster.local"
)

// AltNames contains the domain names and IP addresses that will be added
// to the x509 certificate SubAltNames fields. The values will be passed
// directly to the x509.Certificate object.
type AltNames struct {
	DNSNames []string
	IPs      []net.IP
}

// Config contains the basic fields required for creating a certificate
type Config struct {
	CommonName       string
	Organization     []string
	AltNames         AltNames
	ValidityDuration time.Duration
	CABundleSecret   string
	SigningCASecret  string
	Role             CertificateRole

	// ExtraConfig contains provider specific configurations.
	ExtraConfig map[string]any
}

// CertificateRole identifies the purpose of a certificate issued by a provider.
type CertificateRole string

const (
	CertificateRoleClient CertificateRole = "client"
	CertificateRoleServer CertificateRole = "server"
	CertificateRolePeer   CertificateRole = "peer"
)

type Provider interface {
	// EnsureCASecret ensures the cluster trust-root Secret is available
	// in Kubernetes. The Secret is named `secretKey.Name` in `secretKey.Namespace`
	// and is the single uniform trust root both auto and cert-manager providers
	// materialize for a TLS-enabled EtcdCluster.
	//
	// Implementations:
	//   - auto: generates a per-cluster signing CA and persists the certificate
	//     and private key in the Secret (data keys `ca.crt` and `ca.key`). The
	//     `validity` parameter controls the generated CA's `NotAfter`.
	//   - cert-manager: resolves the configured Issuer/ClusterIssuer and copies
	//     the Issuer's public CA certificate into the Secret (data key `ca.crt`
	//     only; the private key is owned by cert-manager and never exposed).
	//     The `validity` parameter is ignored for cert-manager.
	//
	// Parameters:
	//   - ctx: Context for cancellation and deadlines.
	//   - secretKey: ObjectKey containing the name and namespace of the
	//     cluster trust-root Secret to ensure (typically `<cluster>-ca-tls`).
	//   - validity: Requested CA validity. Honored by auto; ignored by
	//     cert-manager (the Issuer controls its own CA validity).
	//
	// Returns:
	//   - nil if the Secret is ensured, or an error otherwise.
	EnsureCASecret(ctx context.Context, secretKey client.ObjectKey, validity time.Duration) error

	// EnsureCertificateSecret ensures the specified certificate is
	// available as a Secret in Kubernetes. If the Secret does not
	// exist, it will be created.
	//
	// Parameters:
	// - ctx: Context for cancellation and deadlines.
	// - secretKey: ObjectKey containing the name and namespace of the Secret to ensure.
	// - cfg: Configuration for the certificate.
	//
	// Returns:
	// - nil if the operation succeeds, or an error otherwise.
	EnsureCertificateSecret(ctx context.Context, secretKey client.ObjectKey, cfg *Config) error

	// ValidateCertificateSecret validates the certificate stored
	// in the specified Secret. This checks if the certificate is
	// valid (e.g., not expired, matches configuration).
	//
	// Parameters:
	// - ctx: Context for cancellation and deadlines.
	// - secretKey: ObjectKey containing the name and namespace of the Secret to validate.
	// - cfg: Configuration to validate against.
	//
	// Returns:
	// - nil if the Secret is valid, otherwise returns
	//   an error if validation fails.
	ValidateCertificateSecret(ctx context.Context, secretKey client.ObjectKey, cfg *Config) error

	// DeleteCertificateSecret explicitly deletes the Secret containing
	// the certificate. This should only be used if the certificate
	// is no longer needed.
	//
	// Parameters:
	// - ctx: Context for cancellation and deadlines.
	// - secretKey: ObjectKey containing the name and namespace of the Secret to delete.
	//
	// Returns:
	// - nil if the operation succeeds, or an error otherwise.
	DeleteCertificateSecret(ctx context.Context, secretKey client.ObjectKey) error

	// RevokeCertificate revokes a certificate if supported by the provider.
	//
	// Parameters:
	// - ctx: Context for cancellation and deadlines.
	// - secretKey: ObjectKey containing the name and namespace of the Secret containing the certificate to revoke.
	//
	// Returns:
	// - nil if the revocation succeeds, or an error otherwise.
	RevokeCertificate(ctx context.Context, secretKey client.ObjectKey) error

	// GetCertificateConfig returns the certificate configuration from the provider.
	//
	// Parameters:
	// - ctx: Context for cancellation and deadlines.
	// - secretKey: ObjectKey containing the name and namespace of the Secret containing the certificate.
	//
	// Returns:
	// - Config if the Secret exists and is valid, or an error otherwise.
	GetCertificateConfig(ctx context.Context, secretKey client.ObjectKey) (*Config, error)
}
