package cert_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	interfaces "go.etcd.io/etcd-operator/pkg/certificate/interfaces"
)

const (
	testCASecretName     = "etcd-test-ca-tls"
	testCANamespace      = "default"
	testIssuerName       = "test-issuer"
	testIssuerKind       = "Issuer"
	testIssuerSecretName = "test-issuer-ca"
	testClientCertName   = "etcd-test-client-tls"
)

// generateIssuerCA generates a self-signed CA certificate for an Issuer/ClusterIssuer.
// It mirrors the format cert-manager uses for CA-type Issuers.
func generateIssuerCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	require.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "test-issuer-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func newCMTestClient(t *testing.T) (client.Client, *CertManagerProvider) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, certv1.AddToScheme(scheme))
	cli := clientfake.NewClientBuilder().WithScheme(scheme).Build()
	return cli, New(cli).(*CertManagerProvider)
}

// plantIssuerAndSecret creates a CA-type Issuer (or ClusterIssuer) and the Secret it points to.
func plantIssuerAndSecret(t *testing.T, cli client.Client, namespace, name, kind, secretName string, certPEM, keyPEM []byte) {
	t.Helper()
	issuerSpec := certv1.IssuerSpec{
		IssuerConfig: certv1.IssuerConfig{
			CA: &certv1.CAIssuer{SecretName: secretName},
		},
	}
	if kind == "ClusterIssuer" {
		ci := &certv1.ClusterIssuer{
			TypeMeta:   metav1.TypeMeta{Kind: "ClusterIssuer"},
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       issuerSpec,
		}
		require.NoError(t, cli.Create(context.Background(), ci))
	} else {
		iss := &certv1.Issuer{
			TypeMeta:   metav1.TypeMeta{Kind: "Issuer"},
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec:       issuerSpec,
		}
		require.NoError(t, cli.Create(context.Background(), iss))
	}

	// Issuer Secret: store under both `ca.crt` and `tls.crt` for cert-manager compatibility.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt":  certPEM,
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}
	require.NoError(t, cli.Create(context.Background(), secret))
}

// plantLeafCertificate creates a cert-manager Certificate CR with the given issuerRef.
func plantLeafCertificate(t *testing.T, cli client.Client, namespace, name, issuerName, issuerKind string) {
	t.Helper()
	cert := &certv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: certv1.CertificateSpec{
			SecretName: name,
			IssuerRef: cmmeta.IssuerReference{
				Name: issuerName,
				Kind: issuerKind,
			},
		},
	}
	require.NoError(t, cli.Create(context.Background(), cert))
}

func caKey() client.ObjectKey {
	return client.ObjectKey{Name: testCASecretName, Namespace: testCANamespace}
}

// ----------------------------------------------------------------------------
// EnsureCASecret behavior
// ----------------------------------------------------------------------------

func TestEnsureCASecretCreatesWhenAbsent(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))

	got := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), got))
	assert.Equal(t, corev1.SecretTypeOpaque, got.Type)
	assert.Equal(t, certPEM, got.Data["ca.crt"])
	_, hasKey := got.Data["ca.key"]
	assert.False(t, hasKey, "cert-manager CA Secret must not contain ca.key")
}

func TestEnsureCASecretPreservesMatchingSecret(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	// First call creates the Secret.
	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))
	original := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), original))
	originalRV := original.ResourceVersion

	// Second call must not change the Secret.
	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))
	after := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), after))
	assert.Equal(t, originalRV, after.ResourceVersion, "matching content must not be re-applied")
}

func TestEnsureCASecretRefreshesMismatchedSecret(t *testing.T) {
	cli, prov := newCMTestClient(t)
	oldCertPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, oldCertPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))

	// Rotate the Issuer CA by replacing the Issuer Secret's ca.crt data.
	newCertPEM, _ := generateIssuerCA(t)
	issuerSecret := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), client.ObjectKey{Name: testIssuerSecretName, Namespace: testCANamespace}, issuerSecret))
	issuerSecret.Data["ca.crt"] = newCertPEM
	issuerSecret.Data["tls.crt"] = newCertPEM
	require.NoError(t, cli.Update(context.Background(), issuerSecret))

	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))

	got := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), got))
	assert.Equal(t, newCertPEM, got.Data["ca.crt"], "mismatched content must be refreshed")
}

func TestEnsureCASecretMissingIssuer(t *testing.T) {
	cli, prov := newCMTestClient(t)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, "missing-issuer", testIssuerKind)

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-issuer")
}

func TestEnsureCASecretMissingIssuerSecret(t *testing.T) {
	cli, prov := newCMTestClient(t)
	// Plant only the Issuer; reference a Secret that does not exist.
	issuerSpec := certv1.IssuerSpec{
		IssuerConfig: certv1.IssuerConfig{
			CA: &certv1.CAIssuer{SecretName: "non-existent-secret"},
		},
	}
	require.NoError(t, cli.Create(context.Background(), &certv1.Issuer{
		TypeMeta:   metav1.TypeMeta{Kind: "Issuer"},
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testCANamespace},
		Spec:       issuerSpec,
	}))
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-existent-secret")
}

func TestEnsureCASecretRejectsWrongSecretType(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	// Plant a pre-existing CA Secret with the wrong Type.
	require.NoError(t, cli.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testCASecretName, Namespace: testCANamespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{"ca.crt": certPEM},
	}))

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Opaque")
}

func TestEnsureCASecretRequiresExistingLeafCertificate(t *testing.T) {
	_, prov := newCMTestClient(t)
	// No Issuer, no Secret, no leaf planted.

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "leaf")
}

func TestEnsureCASecretSupportsClusterIssuer(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	// ClusterIssuer + Secret in the cluster namespace.
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, "ClusterIssuer", testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, "ClusterIssuer")

	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))

	got := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), got))
	assert.Equal(t, certPEM, got.Data["ca.crt"])
}

func TestEnsureCASecretToleratesCreateRace(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	// Pre-create the Secret so the provider's Create path returns AlreadyExists.
	require.NoError(t, cli.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testCASecretName, Namespace: testCANamespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"ca.crt": certPEM},
	}))

	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))

	got := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), got))
	assert.Equal(t, certPEM, got.Data["ca.crt"])
}

func TestEnsureCASecretRejectsEmptySecretKey(t *testing.T) {
	_, prov := newCMTestClient(t)
	err := prov.EnsureCASecret(context.Background(), client.ObjectKey{Name: "", Namespace: testCANamespace}, 0)
	require.Error(t, err)
	err = prov.EnsureCASecret(context.Background(), client.ObjectKey{Name: testCASecretName, Namespace: ""}, 0)
	require.Error(t, err)
}

// ----------------------------------------------------------------------------
// helper edge cases
// ----------------------------------------------------------------------------

func TestEnsureCASecretFallsBackToFirstCertificateWithoutLeafSuffix(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	// Plant a Certificate with an unusual name (no leaf suffix) but a valid issuerRef.
	plantLeafCertificate(t, cli, testCANamespace, "custom-cert", testIssuerName, testIssuerKind)

	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))

	got := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), got))
	assert.Equal(t, certPEM, got.Data["ca.crt"])
}

func TestEnsureCASecretRejectsUnsupportedIssuerKind(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, "WeirdKind")

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WeirdKind")
}

func TestEnsureCASecretRejectsIssuerWithoutCASecret(t *testing.T) {
	cli, prov := newCMTestClient(t)
	// Issuer Secret exists but contains neither ca.crt nor tls.crt.
	require.NoError(t, cli.Create(context.Background(), &certv1.Issuer{
		TypeMeta:   metav1.TypeMeta{Kind: "Issuer"},
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testCANamespace},
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				CA: &certv1.CAIssuer{SecretName: testIssuerSecretName},
			},
		},
	}))
	require.NoError(t, cli.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerSecretName, Namespace: testCANamespace},
		Data:       map[string][]byte{},
	}))
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ca.crt")
}

func TestEnsureCASecretRejectsMissingIssuerSpec(t *testing.T) {
	cli, prov := newCMTestClient(t)
	// Issuer exists but has no spec.ca configuration.
	require.NoError(t, cli.Create(context.Background(), &certv1.Issuer{
		TypeMeta:   metav1.TypeMeta{Kind: "Issuer"},
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testCANamespace},
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				SelfSigned: &certv1.SelfSignedIssuer{},
			},
		},
	}))
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA configuration")
}

func TestEnsureCASecretRejectsIssuerWithEmptySecretName(t *testing.T) {
	cli, prov := newCMTestClient(t)
	require.NoError(t, cli.Create(context.Background(), &certv1.Issuer{
		TypeMeta:   metav1.TypeMeta{Kind: "Issuer"},
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName, Namespace: testCANamespace},
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				CA: &certv1.CAIssuer{SecretName: ""},
			},
		},
	}))
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secretName")
}

func TestEnsureCASecretRejectsClusterIssuerWithEmptySecretName(t *testing.T) {
	cli, prov := newCMTestClient(t)
	require.NoError(t, cli.Create(context.Background(), &certv1.ClusterIssuer{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterIssuer"},
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName},
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				CA: &certv1.CAIssuer{SecretName: ""},
			},
		},
	}))
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, "ClusterIssuer")

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secretName")
}

func TestEnsureCASecretRejectsClusterIssuerWithoutCASpec(t *testing.T) {
	cli, prov := newCMTestClient(t)
	require.NoError(t, cli.Create(context.Background(), &certv1.ClusterIssuer{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterIssuer"},
		ObjectMeta: metav1.ObjectMeta{Name: testIssuerName},
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				SelfSigned: &certv1.SelfSignedIssuer{},
			},
		},
	}))
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, "ClusterIssuer")

	err := prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA configuration")
}

func TestEnsureCASecretStripsCAKeyFromExistingSecret(t *testing.T) {
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	// Pre-existing CA Secret with ca.crt matching the Issuer AND an extraneous ca.key.
	require.NoError(t, cli.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testCASecretName, Namespace: testCANamespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": certPEM,
			"ca.key": []byte("stale-key"),
		},
	}))

	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))

	got := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), caKey(), got))
	_, hasKey := got.Data["ca.key"]
	assert.False(t, hasKey, "ca.key must be stripped when refreshing an existing Secret")
}

// conflictClient wraps a client.Client and returns Conflict from the first Update
// call on the cluster trust-root Secret, exercising the conflict-handling branch
// of EnsureCASecret without needing real API-server races.
type conflictClient struct {
	client.Client
	failNextUpdate bool
}

func (c *conflictClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if c.failNextUpdate {
		c.failNextUpdate = false
		return k8serrors.NewConflict(
			schemaGroupResource("secret"),
			obj.GetName(),
			fmt.Errorf("simulated conflict"),
		)
	}
	return c.Client.Update(ctx, obj, opts...)
}

func schemaGroupResource(resource string) schema.GroupResource {
	return schema.GroupResource{Group: "", Resource: resource}
}

func TestEnsureCASecretReportsUpdateConflict(t *testing.T) {
	cli, _ := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)

	// Pre-create Secret with mismatched content so EnsureCASecret tries to Update it.
	require.NoError(t, cli.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testCASecretName, Namespace: testCANamespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"ca.crt": []byte("stale")},
	}))

	wrapped := &conflictClient{Client: cli, failNextUpdate: true}
	wrappedProv := New(wrapped).(*CertManagerProvider)

	err := wrappedProv.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conflict")
}

func TestEnsureCASecretCreatesWhenRaceWinnerAppears(t *testing.T) {
	// Seed the underlying store with a pre-existing matching Secret so the
	// Create path inside EnsureCASecret must hit the AlreadyExists tolerance.
	cli, prov := newCMTestClient(t)
	certPEM, _ := generateIssuerCA(t)
	plantIssuerAndSecret(t, cli, testCANamespace, testIssuerName, testIssuerKind, testIssuerSecretName, certPEM, nil)
	plantLeafCertificate(t, cli, testCANamespace, testClientCertName, testIssuerName, testIssuerKind)
	require.NoError(t, cli.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: testCASecretName, Namespace: testCANamespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"ca.crt": certPEM},
	}))
	require.NoError(t, prov.EnsureCASecret(context.Background(), caKey(), interfaces.DefaultCertManagerValidity))
}
