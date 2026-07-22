package auto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	clientfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	interfaces "go.etcd.io/etcd-operator/pkg/certificate/interfaces"
)

const (
	testCAName      = "etcd-test-ca-tls"
	testCANamespace = "default"
	testCAValidity  = 365 * 24 * time.Hour
)

func newCAClient(t *testing.T) (client.Client, *Provider) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := clientfake.NewClientBuilder().WithScheme(scheme).Build()
	return fakeClient, New(fakeClient).(*Provider)
}

func TestGenerateCAProducesValidCAMaterial(t *testing.T) {
	certPEM, keyPEM, err := generateCA(testCAValidity)
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)

	cert, key, err := parseCASecretData("test", certPEM, keyPEM)
	require.NoError(t, err)

	assert.True(t, cert.IsCA, "generated CA must have IsCA=true")
	assert.True(t, cert.BasicConstraintsValid, "generated CA must have valid basic constraints")
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign, cert.KeyUsage, "CA must have CertSign+CRLSign")
	assert.Equal(t, caCommonName, cert.Subject.CommonName)

	_, ok := cert.PublicKey.(*ecdsa.PublicKey)
	assert.True(t, ok, "CA public key must be ECDSA")
	assert.Equal(t, elliptic.P521(), key.Curve, "CA key must be P-521")

	// Validity window: now ≤ NotBefore, NotAfter ≥ now + ~validity
	now := time.Now()
	assert.False(t, cert.NotBefore.After(now), "NotBefore must be ≤ now")
	assert.True(t, cert.NotAfter.After(now.Add(testCAValidity-time.Minute)),
		"NotAfter must cover the requested validity")
}

func TestGenerateCARejectsNonPositiveValidity(t *testing.T) {
	_, _, err := generateCA(0)
	require.Error(t, err)
	_, _, err = generateCA(-time.Hour)
	require.Error(t, err)
}

// ----------------------------------------------------------------------------
// EnsureCASecret behavior
// ----------------------------------------------------------------------------

func TestEnsureCASecretCreatesWhenAbsent(t *testing.T) {
	_, prov := newCAClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}

	require.NoError(t, prov.EnsureCASecret(ctx, secretKey, testCAValidity))

	got := &corev1.Secret{}
	require.NoError(t, prov.Client.Get(ctx, secretKey, got))
	assert.Equal(t, corev1.SecretTypeOpaque, got.Type)
	assert.NotEmpty(t, got.Data[caCertKey])
	assert.NotEmpty(t, got.Data[caKeyKey])
	assert.NotContains(t, got.Data, "tls.key", "CA Secret must not contain leaf tls.key data")
}

func TestEnsureCASecretPreservesValidExisting(t *testing.T) {
	_, prov := newCAClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}

	// First ensure creates the Secret.
	require.NoError(t, prov.EnsureCASecret(ctx, secretKey, testCAValidity))
	original := &corev1.Secret{}
	require.NoError(t, prov.Client.Get(ctx, secretKey, original))
	originalCertPEM := append([]byte(nil), original.Data[caCertKey]...)
	originalKeyPEM := append([]byte(nil), original.Data[caKeyKey]...)

	// Second ensure must not modify data, even when validity differs.
	require.NoError(t, prov.EnsureCASecret(ctx, secretKey, 10*testCAValidity))

	after := &corev1.Secret{}
	require.NoError(t, prov.Client.Get(ctx, secretKey, after))
	assert.Equal(t, originalCertPEM, after.Data[caCertKey], "EnsureCASecret must not replace an existing valid CA certificate")
	assert.Equal(t, originalKeyPEM, after.Data[caKeyKey], "EnsureCASecret must not replace an existing valid CA key")
}

func TestEnsureCASecretRejectsInvalidCAData(t *testing.T) {
	cases := []struct {
		name string
		data map[string][]byte
	}{
		{
			name: "missing ca.crt",
			data: map[string][]byte{caKeyKey: []byte("placeholder")},
		},
		{
			name: "missing ca.key",
			data: map[string][]byte{caCertKey: []byte("placeholder")},
		},
		{
			name: "invalid ca.crt PEM",
			data: map[string][]byte{caCertKey: []byte("not-pem"), caKeyKey: []byte("not-pem")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli, prov := newCAClient(t)
			ctx := context.Background()
			secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}
			require.NoError(t, cli.Create(ctx, &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
				Type:       corev1.SecretTypeOpaque,
				Data:       tc.data,
			}))

			err := prov.EnsureCASecret(ctx, secretKey, testCAValidity)
			require.Error(t, err)

			// Ensure the bad data was not overwritten.
			after := &corev1.Secret{}
			require.NoError(t, cli.Get(ctx, secretKey, after))
			assert.Equal(t, tc.data, after.Data)
		})
	}
}

func TestEnsureCASecretRejectsMismatchedKeyPair(t *testing.T) {
	cli, prov := newCAClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}

	// Generate one CA cert and a *different* EC key.
	certPEM, _, err := generateCA(testCAValidity)
	require.NoError(t, err)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	wrongKeyDER, err := x509.MarshalECPrivateKey(wrongKey)
	require.NoError(t, err)
	wrongKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: wrongKeyDER})

	require.NoError(t, cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{caCertKey: certPEM, caKeyKey: wrongKeyPEM},
	}))

	err = prov.EnsureCASecret(ctx, secretKey, testCAValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

func TestEnsureCASecretRejectsNonCASecretType(t *testing.T) {
	cli, prov := newCAClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}

	// Plant a Secret of the wrong type but with valid CA material.
	certPEM, keyPEM, err := generateCA(testCAValidity)
	require.NoError(t, err)
	require.NoError(t, cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data:       map[string][]byte{caCertKey: certPEM, caKeyKey: keyPEM},
	}))

	err = prov.EnsureCASecret(ctx, secretKey, testCAValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Opaque")
}

func TestEnsureCASecretToleratesCreateRace(t *testing.T) {
	_, prov := newCAClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}

	// First create: succeeds.
	require.NoError(t, prov.EnsureCASecret(ctx, secretKey, testCAValidity))
	original := &corev1.Secret{}
	require.NoError(t, prov.Client.Get(ctx, secretKey, original))
	originalUID := original.UID

	// Simulate a second reconciler racing: directly attempt a Create on a
	// client that already has the Secret. The provider's EnsureCASecret must
	// observe the existing Secret and validate it without erroring.
	duplicated := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretKey.Name,
			Namespace: secretKey.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caCertKey: original.Data[caCertKey],
			caKeyKey:  original.Data[caKeyKey],
		},
	}
	err := prov.Create(ctx, duplicated)
	require.True(t, err != nil, "raw create of a duplicate Secret must report an error so the provider can fall through to validation")

	require.NoError(t, prov.EnsureCASecret(ctx, secretKey, testCAValidity))
	after := &corev1.Secret{}
	require.NoError(t, prov.Client.Get(ctx, secretKey, after))
	assert.Equal(t, originalUID, after.UID, "winner of the create race must remain the canonical Secret")
}

func TestEnsureCASecretRejectsExpiredCA(t *testing.T) {
	cli, prov := newCAClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}

	// Build a CA whose NotAfter is in the past.
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "expired-ca"},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(-time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	require.NoError(t, cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{caCertKey: certPEM, caKeyKey: keyPEM},
	}))

	err = prov.EnsureCASecret(ctx, secretKey, testCAValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestEnsureCASecretRejectsNotYetValidCA(t *testing.T) {
	cli, prov := newCAClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: testCAName, Namespace: testCANamespace}

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "future-ca"},
		NotBefore:             now.Add(time.Hour),
		NotAfter:              now.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	require.NoError(t, cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{caCertKey: certPEM, caKeyKey: keyPEM},
	}))

	err = prov.EnsureCASecret(ctx, secretKey, testCAValidity)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet valid")
}

func TestEnsureCASecretRejectsEmptySecretKey(t *testing.T) {
	cli, prov := newCAClient(t)
	ctx := context.Background()
	err := prov.EnsureCASecret(ctx, client.ObjectKey{Name: "", Namespace: testCANamespace}, testCAValidity)
	require.Error(t, err)
	err = prov.EnsureCASecret(ctx, client.ObjectKey{Name: testCAName, Namespace: ""}, testCAValidity)
	require.Error(t, err)
	_ = cli
}

// Compile-time guard: the auto provider implements both interfaces.
var _ interfaces.Provider = (*Provider)(nil)
var _ interfaces.CertificateAuthorityProvider = (*Provider)(nil)
