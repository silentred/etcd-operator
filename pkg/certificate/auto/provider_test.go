package auto

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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

func newTestClient(t *testing.T) (client.Client, *Provider) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	cli := clientfake.NewClientBuilder().WithScheme(scheme).Build()
	return cli, New(cli).(*Provider)
}

// plantCASecret generates a fresh CA and writes it into the fake client under
// the supplied Secret key. Tests use it to set up the precondition for leaf
// operations without going through EnsureCASecret.
func plantCASecret(t *testing.T, cli client.Client, key client.ObjectKey, validity time.Duration) {
	t.Helper()
	certPEM, keyPEM, err := generateCA(validity)
	require.NoError(t, err)
	require.NoError(t, cli.Create(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			caCertKey: certPEM,
			caKeyKey:  keyPEM,
		},
	}))
}

// readCAFromSecret returns the parsed CA from the Secret, for chain validation
// in tests.
func readCAFromSecret(t *testing.T, cli client.Client, key client.ObjectKey) *x509.Certificate {
	t.Helper()
	s := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), key, s))
	cert, _, err := parseCASecret(s)
	require.NoError(t, err)
	return cert
}

// TestEnsureCertificateSecretCertHasClientAuth exercises the integration
// between EnsureCertificateSecret and the per-cluster CA for the client
// certificate. The resulting leaf must carry ClientAuth so the etcd client
// listener trusts the operator when it presents the separate client Secret.
func TestEnsureCertificateSecretCertHasClientAuth(t *testing.T) {
	cli, prov := newTestClient(t)
	ctx := context.Background()
	caKey := client.ObjectKey{Name: "etcd-test-ca-tls", Namespace: "default"}
	plantCASecret(t, cli, caKey, interfaces.DefaultAutoValidity)

	secretKey := client.ObjectKey{Name: "etcd-test-client-tls", Namespace: "default"}
	cfg := &interfaces.Config{
		CommonName:       "etcd.test",
		ValidityDuration: interfaces.DefaultAutoValidity,
		SigningCASecret:  caKey.Name,
		Role:             interfaces.CertificateRoleClient,
		AltNames: interfaces.AltNames{
			DNSNames: []string{"etcd.test.default.svc.cluster.local"},
		},
	}

	require.NoError(t, prov.EnsureCertificateSecret(ctx, secretKey, cfg))

	secret := &corev1.Secret{}
	require.NoError(t, cli.Get(ctx, secretKey, secret))
	assert.Equal(t, corev1.SecretTypeTLS, secret.Type)
	require.NotEmpty(t, secret.Data["tls.crt"])
	require.NotEmpty(t, secret.Data["tls.key"])
	require.NotEmpty(t, secret.Data["ca.crt"])

	block, _ := pem.Decode(secret.Data["tls.crt"])
	require.NotNil(t, block, "tls.crt is valid PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	assert.Contains(t, cert.ExtKeyUsage, x509.ExtKeyUsageClientAuth,
		"client leaf must carry ClientAuth so the operator can present it as a client (design D4-a)")
	assert.False(t, cert.IsCA, "leaf must not be a CA")

	// The leaf must be signed by the planted CA.
	caCert := readCAFromSecret(t, cli, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	_, verifyErr := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, verifyErr, "client leaf must verify under the shared CA")
}

// ----------------------------------------------------------------------------
// Group 3 leaf issuance scenarios
// ----------------------------------------------------------------------------

func TestEnsureLeafSecret_RejectsMissingConfig(t *testing.T) {
	_, prov := newTestClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: "x", Namespace: "default"}
	err := prov.EnsureCertificateSecret(ctx, secretKey, nil)
	require.Error(t, err)
	cfg := &interfaces.Config{Role: interfaces.CertificateRoleClient}
	err = prov.EnsureCertificateSecret(ctx, secretKey, cfg)
	require.Error(t, err)
	cfg.SigningCASecret = "etcd-x-ca-tls"
	cfg.Role = ""
	err = prov.EnsureCertificateSecret(ctx, secretKey, cfg)
	require.Error(t, err)
}

func TestEnsureLeafSecret_RequiresExistingCA(t *testing.T) {
	_, prov := newTestClient(t)
	ctx := context.Background()
	secretKey := client.ObjectKey{Name: "etcd-x-client-tls", Namespace: "default"}
	cfg := &interfaces.Config{
		CommonName:       "client",
		ValidityDuration: interfaces.DefaultAutoValidity,
		SigningCASecret:  "etcd-x-ca-tls",
		Role:             interfaces.CertificateRoleClient,
	}
	err := prov.EnsureCertificateSecret(ctx, secretKey, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shared CA secret")
}

func TestEnsureLeafSecret_IssuesClientServerPeer(t *testing.T) {
	cli, prov := newTestClient(t)
	ctx := context.Background()
	caKey := client.ObjectKey{Name: "etcd-x-ca-tls", Namespace: "default"}
	plantCASecret(t, cli, caKey, interfaces.DefaultAutoValidity)
	caCert := readCAFromSecret(t, cli, caKey)

	roleCases := []struct {
		name string
		role interfaces.CertificateRole
		want []x509.ExtKeyUsage
	}{
		{"client", interfaces.CertificateRoleClient, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"server", interfaces.CertificateRoleServer, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"peer", interfaces.CertificateRolePeer, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
	}

	for _, tc := range roleCases {
		t.Run(tc.name, func(t *testing.T) {
			secretKey := client.ObjectKey{Name: "etcd-x-" + tc.name + "-tls", Namespace: "default"}
			cfg := &interfaces.Config{
				CommonName:       tc.name + ".test",
				ValidityDuration: interfaces.DefaultAutoValidity,
				SigningCASecret:  caKey.Name,
				Role:             tc.role,
			}
			require.NoError(t, prov.EnsureCertificateSecret(ctx, secretKey, cfg))

			secret := &corev1.Secret{}
			require.NoError(t, cli.Get(ctx, secretKey, secret))
			assert.Equal(t, corev1.SecretTypeTLS, secret.Type)
			assert.NotContains(t, secret.Data, caKeyKey, "leaf secret must never carry the CA private key")

			block, _ := pem.Decode(secret.Data["tls.crt"])
			require.NotNil(t, block)
			cert, err := x509.ParseCertificate(block.Bytes)
			require.NoError(t, err)
			assert.False(t, cert.IsCA, "leaf must not be a CA")
			assert.ElementsMatch(t, tc.want, cert.ExtKeyUsage)

			pool := x509.NewCertPool()
			pool.AddCert(caCert)
			_, verifyErr := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: tc.want})
			require.NoError(t, verifyErr, "leaf must verify under the shared CA")
		})
	}
}

func TestEnsureLeafSecret_PreservesExistingValid(t *testing.T) {
	cli, prov := newTestClient(t)
	ctx := context.Background()
	caKey := client.ObjectKey{Name: "etcd-x-ca-tls", Namespace: "default"}
	plantCASecret(t, cli, caKey, interfaces.DefaultAutoValidity)

	secretKey := client.ObjectKey{Name: "etcd-x-server-tls", Namespace: "default"}
	cfg := &interfaces.Config{
		CommonName:       "server.test",
		ValidityDuration: interfaces.DefaultAutoValidity,
		SigningCASecret:  caKey.Name,
		Role:             interfaces.CertificateRoleServer,
		AltNames:         interfaces.AltNames{DNSNames: []string{"server.test"}},
	}
	require.NoError(t, prov.EnsureCertificateSecret(ctx, secretKey, cfg))
	original := &corev1.Secret{}
	require.NoError(t, cli.Get(ctx, secretKey, original))
	originalCertPEM := append([]byte(nil), original.Data["tls.crt"]...)
	originalKeyPEM := append([]byte(nil), original.Data["tls.key"]...)

	// Second ensure must not regenerate the leaf.
	require.NoError(t, prov.EnsureCertificateSecret(ctx, secretKey, cfg))
	after := &corev1.Secret{}
	require.NoError(t, cli.Get(ctx, secretKey, after))
	assert.Equal(t, originalCertPEM, after.Data["tls.crt"], "valid leaf certificate must be preserved")
	assert.Equal(t, originalKeyPEM, after.Data["tls.key"], "valid leaf private key must be preserved")
}

func TestEnsureLeafSecret_RejectsUnrelatedIssuer(t *testing.T) {
	cli, prov := newTestClient(t)
	ctx := context.Background()
	caKey := client.ObjectKey{Name: "etcd-x-ca-tls", Namespace: "default"}
	plantCASecret(t, cli, caKey, interfaces.DefaultAutoValidity)

	// Plant a leaf signed by a different CA entirely.
	otherCAPEM, otherCAKey, err := generateCA(interfaces.DefaultAutoValidity)
	require.NoError(t, err)
	otherCertPEM, otherLeafKeyPEM, err := signLeafManually(t, otherCAPEM, otherCAKey, &interfaces.Config{
		CommonName:       "rogue.test",
		ValidityDuration: interfaces.DefaultAutoValidity,
		Role:             interfaces.CertificateRoleServer,
	})
	require.NoError(t, err)
	secretKey := client.ObjectKey{Name: "etcd-x-server-tls", Namespace: "default"}
	require.NoError(t, cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": otherCertPEM,
			"tls.key": otherLeafKeyPEM,
			"ca.crt":  otherCAPEM,
		},
	}))

	cfg := &interfaces.Config{
		CommonName:       "server.test",
		ValidityDuration: interfaces.DefaultAutoValidity,
		SigningCASecret:  caKey.Name,
		Role:             interfaces.CertificateRoleServer,
	}
	err = prov.EnsureCertificateSecret(ctx, secretKey, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shared CA")

	// The existing Secret must be untouched.
	after := &corev1.Secret{}
	require.NoError(t, cli.Get(ctx, secretKey, after))
	assert.Equal(t, otherCertPEM, after.Data["tls.crt"], "unrelated leaf must not be silently replaced")
}

func TestEnsureLeafSecret_RejectsWrongRoleEKU(t *testing.T) {
	cli, prov := newTestClient(t)
	ctx := context.Background()
	caKey := client.ObjectKey{Name: "etcd-x-ca-tls", Namespace: "default"}
	plantCASecret(t, cli, caKey, interfaces.DefaultAutoValidity)

	// Plant a leaf whose EKU is ClientAuth only, but the caller asks for the
	// server role. Validation must reject the mismatch.
	certPEM, keyPEM, err := signLeafManually(t, mustCAPEM(t, cli, caKey), mustCAKey(t, cli, caKey), &interfaces.Config{
		CommonName:       "client-only.test",
		ValidityDuration: interfaces.DefaultAutoValidity,
		Role:             interfaces.CertificateRoleClient,
	})
	require.NoError(t, err)
	secretKey := client.ObjectKey{Name: "etcd-x-server-tls", Namespace: "default"}
	require.NoError(t, cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: secretKey.Name, Namespace: secretKey.Namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
			"ca.crt":  mustCAPEM(t, cli, caKey),
		},
	}))

	cfg := &interfaces.Config{
		CommonName:       "server.test",
		ValidityDuration: interfaces.DefaultAutoValidity,
		SigningCASecret:  caKey.Name,
		Role:             interfaces.CertificateRoleServer,
	}
	err = prov.EnsureCertificateSecret(ctx, secretKey, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shared CA")
}

// signLeafManually is a test helper that uses the same internal APIs to
// produce a leaf signed by a given CA without going through EnsureCertificateSecret.
func signLeafManually(t *testing.T, caPEM, caKeyPEM []byte, cfg *interfaces.Config) (certPEM, keyPEM []byte, err error) {
	t.Helper()
	caCert, caPriv, err := parseCASecretData("inline-ca", caPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	leaf, leafKey, err := createLeafCert(caCert, caPriv, cfg)
	if err != nil {
		return nil, nil, err
	}
	return encodeLeafPEM(leaf, leafKey)
}

func mustCAPEM(t *testing.T, cli client.Client, key client.ObjectKey) []byte {
	t.Helper()
	s := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), key, s))
	return s.Data[caCertKey]
}

func mustCAKey(t *testing.T, cli client.Client, key client.ObjectKey) []byte {
	t.Helper()
	s := &corev1.Secret{}
	require.NoError(t, cli.Get(context.Background(), key, s))
	return s.Data[caKeyKey]
}

func TestEnsureLeafSecret_RejectsLeafValidityBeyondCA(t *testing.T) {
	cli, prov := newTestClient(t)
	ctx := context.Background()
	caKey := client.ObjectKey{Name: "etcd-x-ca-tls", Namespace: "default"}
	// CA valid for 1 day, leaf request 1 year: must be rejected.
	plantCASecret(t, cli, caKey, 24*time.Hour)

	secretKey := client.ObjectKey{Name: "etcd-x-server-tls", Namespace: "default"}
	cfg := &interfaces.Config{
		CommonName:       "server.test",
		ValidityDuration: 365 * 24 * time.Hour,
		SigningCASecret:  caKey.Name,
		Role:             interfaces.CertificateRoleServer,
	}
	err := prov.EnsureCertificateSecret(ctx, secretKey, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CA validity")
}
