package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
	certv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"

	ecv1alpha1 "go.etcd.io/etcd-operator/api/v1alpha1"
	"go.etcd.io/etcd-operator/pkg/certificate"
	certInterface "go.etcd.io/etcd-operator/pkg/certificate/interfaces"
)

func pointerToBool(value bool) *bool {
	return &value
}

// ---------------------------------------------------------------------------
// createHeadlessServiceIfNotExist
// ---------------------------------------------------------------------------

func TestCreateHeadlessServiceIfNotExist(t *testing.T) {
	ctx := t.Context()
	logger := log.FromContext(ctx)

	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = ecv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "test-etcd", Namespace: "default"},
	}

	t.Run("creates headless service if it does not exist", func(t *testing.T) {
		err := createHeadlessServiceIfNotExist(ctx, logger, fakeClient, ec, scheme)
		assert.NoError(t, err)

		service := &corev1.Service{}
		err = fakeClient.Get(ctx, client.ObjectKey{Name: "test-etcd", Namespace: "default"}, service)
		assert.NoError(t, err)
		assert.Equal(t, "None", service.Spec.ClusterIP)
		assert.Equal(t, map[string]string{
			"app":        "test-etcd",
			"controller": "test-etcd",
		}, service.Spec.Selector)
		// PublishNotReadyAddresses must be true so that during a cluster scale-out
		// (e.g. 1->3 nodes), CoreDNS returns the NotReady new member's Pod IP in
		// the headless Service's A record set. etcd v3.6's peer-port checkCertSAN
		// does a forward-DNS lookup of the cert's DNSName against the connecting
		// pod IP; without this flag, the new member's IP is missing from the
		// lookup result, peer TLS handshake fails ("tls: \"<ip>\" does not match any
		// of DNSNames"), etcd bootstrap dies, and the new pod never becomes Ready.
		// See analysis in internal/controller/utils.go createHeadlessServiceIfNotExist.
		assert.True(t, service.Spec.PublishNotReadyAddresses,
			"headless Service for an etcd cluster MUST publish not-ready addresses; otherwise peer-bootstrap TLS hangs forever")
		require.Len(t, service.OwnerReferences, 1)
		assert.Equal(t, ec.Name, service.OwnerReferences[0].Name)
	})

	t.Run("does not create service if it already exists", func(t *testing.T) {
		err := createHeadlessServiceIfNotExist(ctx, logger, fakeClient, ec, scheme)
		assert.NoError(t, err)
	})
}

// ---------------------------------------------------------------------------
// validateEtcdUpgradePath
// ---------------------------------------------------------------------------

func TestValidateEtcdUpgradePath(t *testing.T) {
	etcdVersions := []semver.Version{
		{Major: 3, Minor: 0},
		{Major: 3, Minor: 1},
		{Major: 3, Minor: 2},
		{Major: 3, Minor: 3},
		{Major: 3, Minor: 4},
		{Major: 3, Minor: 5},
		{Major: 3, Minor: 6},
		{Major: 3, Minor: 7},
		{Major: 4, Minor: 0},
	}

	tests := []struct {
		name      string
		current   string
		target    string
		canParse  bool
		expectErr bool
	}{
		{name: "equal versions", current: "3.2.0", target: "3.2.0", canParse: true, expectErr: false},
		{name: "valid minor level upgrade", current: "3.4.0", target: "3.5.0", canParse: true, expectErr: false},
		{name: "valid patch level upgrade", current: "3.4.0", target: "3.4.1", canParse: true, expectErr: false},
		{name: "invalid current version", current: "invalid", target: "3.1.0", canParse: false, expectErr: true},
		{name: "invalid target version", current: "3.1.0", target: "invalid", canParse: false, expectErr: true},
		{name: "minor downgrade not allowed", current: "3.2.0", target: "3.1.0", canParse: true, expectErr: true},
		{name: "patch downgrade not allowed", current: "3.5.1", target: "3.5.0", canParse: true, expectErr: true},
		{name: "unknown current version", current: "3.9.0", target: "4.0.0", canParse: true, expectErr: true},
		{name: "unknown target version", current: "4.0.0", target: "4.1.0", canParse: true, expectErr: true},
		{name: "invalid upgrade skipping minor", current: "3.4.0", target: "3.6.0", canParse: true, expectErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canParse, err := validateEtcdUpgradePath(etcdVersions, tt.current, tt.target)
			if canParse != tt.canParse {
				t.Fatalf("expected canParse=%v, got %v", tt.canParse, canParse)
			}
			if tt.expectErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Fatalf("did not expect error, got %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Certificate config helpers
// ---------------------------------------------------------------------------

func TestCreateAutoCertificateConfig(t *testing.T) {
	tests := []struct {
		name     string
		ec       *ecv1alpha1.EtcdCluster
		expected *certInterface.Config
		wantErr  bool
	}{
		{
			name: "auto config with all fields set",
			ec: &ecv1alpha1.EtcdCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "test-namespace"},
				Spec: ecv1alpha1.EtcdClusterSpec{
					TLS: &ecv1alpha1.TLSCertificate{
						Provider: string(certificate.Auto),
						ProviderCfg: ecv1alpha1.ProviderConfig{
							AutoCfg: &ecv1alpha1.ProviderAutoConfig{
								CommonConfig: ecv1alpha1.CommonConfig{
									CommonName:       "custom.example.com",
									Organization:     []string{"Test Org"},
									ValidityDuration: "720h",
									AltNames: ecv1alpha1.AltNames{
										DNSNames: []string{"custom1.example.com", "custom2.example.com"},
										IPs:      []net.IP{net.ParseIP("10.0.0.1")},
									},
								},
							},
						},
					},
				},
			},
			expected: &certInterface.Config{
				CommonName:       "custom.example.com",
				Organization:     []string{"Test Org"},
				ValidityDuration: 720 * time.Hour,
				AltNames: certInterface.AltNames{
					DNSNames: []string{"custom1.example.com", "custom2.example.com"},
					IPs:      []net.IP{net.ParseIP("10.0.0.1")},
				},
				Role:            certInterface.CertificateRoleServer,
				SigningCASecret: "test-cluster-ca-tls",
			},
			wantErr: false,
		},
		{
			name: "auto config with nil AutoCfg — uses defaults",
			ec: &ecv1alpha1.EtcdCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "test-namespace"},
				Spec: ecv1alpha1.EtcdClusterSpec{
					TLS: &ecv1alpha1.TLSCertificate{
						Provider:    string(certificate.Auto),
						ProviderCfg: ecv1alpha1.ProviderConfig{AutoCfg: nil},
					},
				},
			},
			expected: &certInterface.Config{
				CommonName:       "test-cluster.test-namespace.svc.cluster.local",
				Organization:     nil,
				ValidityDuration: certInterface.DefaultAutoValidity,
				AltNames: certInterface.AltNames{
					DNSNames: []string{
						"*.test-cluster.test-namespace.svc.cluster.local",
						"test-cluster.test-namespace.svc.cluster.local",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := createAutoCertificateConfig(tt.ec, certInterface.CertificateRoleServer)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expected.CommonName, result.CommonName)
				assert.Equal(t, tt.expected.Organization, result.Organization)
				assert.Equal(t, tt.expected.ValidityDuration, result.ValidityDuration)
				assert.Equal(t, tt.expected.AltNames.DNSNames, result.AltNames.DNSNames)
				assert.Equal(t, tt.expected.AltNames.IPs, result.AltNames.IPs)
			}
		})
	}
}

func TestCreateCMCertificateConfig(t *testing.T) {
	tests := []struct {
		name     string
		ec       *ecv1alpha1.EtcdCluster
		expected *certInterface.Config
		wantErr  bool
	}{
		{
			name: "cert-manager config with all fields set",
			ec: &ecv1alpha1.EtcdCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "test-namespace"},
				Spec: ecv1alpha1.EtcdClusterSpec{
					TLS: &ecv1alpha1.TLSCertificate{
						Provider: string(certificate.CertManager),
						ProviderCfg: ecv1alpha1.ProviderConfig{
							CertManagerCfg: &ecv1alpha1.ProviderCertManagerConfig{
								CommonConfig: ecv1alpha1.CommonConfig{
									CommonName:       "cm.example.com",
									Organization:     []string{"CM Org"},
									ValidityDuration: "1440h",
									AltNames: ecv1alpha1.AltNames{
										DNSNames: []string{"cm1.example.com", "cm2.example.com"},
									},
								},
								IssuerName: "test-issuer",
								IssuerKind: "ClusterIssuer",
							},
						},
					},
				},
			},
			expected: &certInterface.Config{
				CommonName:       "cm.example.com",
				Organization:     []string{"CM Org"},
				ValidityDuration: 1440 * time.Hour,
				AltNames: certInterface.AltNames{
					DNSNames: []string{"cm1.example.com", "cm2.example.com"},
				},
				Role: certInterface.CertificateRoleServer,
				ExtraConfig: map[string]any{
					"issuerName": "test-issuer",
					"issuerKind": "ClusterIssuer",
				},
			},
			wantErr: false,
		},
		{
			name: "cert-manager config with nil CertManagerCfg",
			ec: &ecv1alpha1.EtcdCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "test-cluster", Namespace: "test-namespace"},
				Spec: ecv1alpha1.EtcdClusterSpec{
					TLS: &ecv1alpha1.TLSCertificate{
						Provider:    string(certificate.CertManager),
						ProviderCfg: ecv1alpha1.ProviderConfig{CertManagerCfg: nil},
					},
				},
			},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := createCMCertificateConfig(tt.ec, certInterface.CertificateRoleServer)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.expected.CommonName, result.CommonName)
				assert.Equal(t, tt.expected.Organization, result.Organization)
				assert.Equal(t, tt.expected.ValidityDuration, result.ValidityDuration)
				assert.Equal(t, tt.expected.AltNames.DNSNames, result.AltNames.DNSNames)
				assert.Equal(t, tt.expected.AltNames.IPs, result.AltNames.IPs)
				assert.Equal(t, tt.expected.ExtraConfig, result.ExtraConfig)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// peerEndpointForOrdinalIndex — scheme reflects TLS configuration
// ---------------------------------------------------------------------------

func TestPeerEndpointForOrdinal(t *testing.T) {
	mkCluster := func(name, namespace string, tls *ecv1alpha1.TLSCertificate) *ecv1alpha1.EtcdCluster {
		return &ecv1alpha1.EtcdCluster{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: "1"},
			Spec:       ecv1alpha1.EtcdClusterSpec{TLS: tls},
		}
	}

	httpCluster := mkCluster("test-cluster", "default", nil)
	httpsCluster := mkCluster("test-cluster", "default", &ecv1alpha1.TLSCertificate{Provider: "auto"})

	// Replace the trailing scheme expectations; the member name is scheme-agnostic.
	const wantName = "test-cluster-0"
	httpName, httpURL := peerEndpointForOrdinalIndex(httpCluster, 0)
	httpsName, httpsURL := peerEndpointForOrdinalIndex(httpsCluster, 0)

	assert.Equal(t, wantName, httpName)
	assert.Equal(t, wantName, httpsName)

	assert.Equal(t, "http://test-cluster-0.test-cluster.default.svc.cluster.local:2380", httpURL)
	assert.Equal(t, "https://test-cluster-0.test-cluster.default.svc.cluster.local:2380", httpsURL)
}

// ---------------------------------------------------------------------------
// verifySecretHasCA — error path when a cert Secret lacks ca.crt
// ---------------------------------------------------------------------------

func TestVerifySecretHasCA(t *testing.T) {
	mkSecret := func(data map[string][]byte) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "x-tls", Namespace: "default"},
			Data:       data,
		}
	}

	t.Run("with ca.crt passes", func(t *testing.T) {
		err := verifySecretHasCA(mkSecret(map[string][]byte{
			"tls.crt": []byte("cert"),
			"tls.key": []byte("key"),
			"ca.crt":  []byte("ca"),
		}), string(certificate.Auto))
		assert.NoError(t, err)
	})

	t.Run("without ca.crt errors with provider hint", func(t *testing.T) {
		err := verifySecretHasCA(mkSecret(map[string][]byte{
			"tls.crt": []byte("cert"),
			"tls.key": []byte("key"),
		}), string(certificate.CertManager))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ca.crt")
		assert.Contains(t, err.Error(), "cert-manager")
	})
}

// ---------------------------------------------------------------------------
// CA Secret naming and role-aware configuration helpers
// ---------------------------------------------------------------------------

func TestGetCASecretName(t *testing.T) {
	assert.Equal(t, "etcd-test-ca-tls", getCASecretName("etcd-test"))
	assert.Equal(t, "cluster-ca-tls", getCASecretName("cluster"))
}

func TestCreateAutoCertificateConfig_PropagatesRoleAndCA(t *testing.T) {
	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-x", Namespace: "ns-x"},
		Spec: ecv1alpha1.EtcdClusterSpec{
			TLS: &ecv1alpha1.TLSCertificate{
				Provider: string(certificate.Auto),
				ProviderCfg: ecv1alpha1.ProviderConfig{
					AutoCfg: &ecv1alpha1.ProviderAutoConfig{
						CommonConfig: ecv1alpha1.CommonConfig{},
					},
				},
			},
		},
	}

	tests := []struct {
		name string
		role certInterface.CertificateRole
	}{
		{name: "client role", role: certInterface.CertificateRoleClient},
		{name: "server role", role: certInterface.CertificateRoleServer},
		{name: "peer role", role: certInterface.CertificateRolePeer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := createAutoCertificateConfig(ec, tt.role)
			require.NoError(t, err)
			require.NotNil(t, cfg)
			assert.Equal(t, tt.role, cfg.Role)
			assert.Equal(t, getCASecretName(ec.Name), cfg.SigningCASecret)
		})
	}
}

func TestCreateAutoCertificateConfig_PreservesIPAddresses(t *testing.T) {
	ip1 := net.ParseIP("10.0.0.1")
	ip2 := net.ParseIP("fd00::1")

	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-ip", Namespace: "ns"},
		Spec: ecv1alpha1.EtcdClusterSpec{
			TLS: &ecv1alpha1.TLSCertificate{
				Provider: string(certificate.Auto),
				ProviderCfg: ecv1alpha1.ProviderConfig{
					AutoCfg: &ecv1alpha1.ProviderAutoConfig{
						CommonConfig: ecv1alpha1.CommonConfig{
							AltNames: ecv1alpha1.AltNames{
								DNSNames: []string{"a.example.com", "b.example.com"},
								IPs:      []net.IP{ip1, ip2},
							},
						},
					},
				},
			},
		},
	}

	cfg, err := createAutoCertificateConfig(ec, certInterface.CertificateRoleServer)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Len(t, cfg.AltNames.IPs, 2)
	assert.True(t, cfg.AltNames.IPs[0].Equal(ip1), "first IP must be the configured 10.0.0.1, not a zero-value placeholder")
	assert.True(t, cfg.AltNames.IPs[1].Equal(ip2), "second IP must be the configured fd00::1, not a zero-value placeholder")
}

func TestCreateCMCertificateConfig_PreservesIPAddresses(t *testing.T) {
	ip := net.ParseIP("192.0.2.10")
	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-cm", Namespace: "ns"},
		Spec: ecv1alpha1.EtcdClusterSpec{
			TLS: &ecv1alpha1.TLSCertificate{
				Provider: string(certificate.CertManager),
				ProviderCfg: ecv1alpha1.ProviderConfig{
					CertManagerCfg: &ecv1alpha1.ProviderCertManagerConfig{
						CommonConfig: ecv1alpha1.CommonConfig{
							AltNames: ecv1alpha1.AltNames{
								IPs: []net.IP{ip},
							},
						},
						IssuerName: "i",
						IssuerKind: "Issuer",
					},
				},
			},
		},
	}

	cfg, err := createCMCertificateConfig(ec, certInterface.CertificateRoleServer)
	require.NoError(t, err)
	require.Len(t, cfg.AltNames.IPs, 1)
	assert.True(t, cfg.AltNames.IPs[0].Equal(ip))
}

// ---------------------------------------------------------------------------
// CA-first orchestration
// ---------------------------------------------------------------------------

func TestEnsureAutoTLSCertificates_CreatesCAFirstAndSetsOwnership(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, ecv1alpha1.AddToScheme(scheme))

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-ca-first", Namespace: "default", UID: "uid-ca-first"},
		Spec: ecv1alpha1.EtcdClusterSpec{
			TLS: &ecv1alpha1.TLSCertificate{Provider: string(certificate.Auto)},
		},
	}

	require.NoError(t, ensureClusterTLS(t.Context(), ec, cli))

	// All four Secrets must exist.
	for _, name := range []string{
		getCASecretName(ec.Name),
		getClientCertName(ec.Name),
		getServerCertName(ec.Name),
		getPeerCertName(ec.Name),
	} {
		s := &corev1.Secret{}
		require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Name: name, Namespace: ec.Namespace}, s),
			"missing TLS Secret %s after ensure", name)
		require.Len(t, s.OwnerReferences, 1, "TLS Secret %s must carry an owner reference", name)
		assert.Equal(t, ec.Name, s.OwnerReferences[0].Name)
	}
}

func TestEnsureAutoTLSCertificates_PreservesCAOnRepeat(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, ecv1alpha1.AddToScheme(scheme))
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-repeat", Namespace: "default", UID: "uid-repeat"},
		Spec:       ecv1alpha1.EtcdClusterSpec{TLS: &ecv1alpha1.TLSCertificate{Provider: string(certificate.Auto)}},
	}

	require.NoError(t, ensureClusterTLS(t.Context(), ec, cli))
	caSecret := &corev1.Secret{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Name: getCASecretName(ec.Name), Namespace: ec.Namespace}, caSecret))
	originalCAUID := caSecret.UID

	require.NoError(t, ensureClusterTLS(t.Context(), ec, cli))
	after := &corev1.Secret{}
	require.NoError(t, cli.Get(t.Context(), client.ObjectKey{Name: getCASecretName(ec.Name), Namespace: ec.Namespace}, after))
	assert.Equal(t, originalCAUID, after.UID, "shared CA Secret must not be replaced across reconciles")
}

func TestEnsureAutoTLSCertificates_SkipsForPlaintext(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-plain", Namespace: "default"},
		Spec:       ecv1alpha1.EtcdClusterSpec{}, // no TLS
	}

	require.NoError(t, ensureClusterTLS(t.Context(), ec, cli))

	for _, name := range []string{
		getCASecretName(ec.Name),
		getClientCertName(ec.Name),
		getServerCertName(ec.Name),
		getPeerCertName(ec.Name),
	} {
		s := &corev1.Secret{}
		err := cli.Get(t.Context(), client.ObjectKey{Name: name, Namespace: ec.Namespace}, s)
		require.True(t, err != nil && k8serrors.IsNotFound(err),
			"plaintext cluster must not create TLS Secret %s", name)
	}
}

func TestEnsureAutoTLSCertificates_DelegatesToCertManagerPath(t *testing.T) {
	// Cert-manager path requires the cert-manager CRDs. The CRD not being
	// registered is itself proof that the controller does not go through the
	// auto-provider CA ensure. We assert that the CA Secret is not created
	// when TLS.Provider is cert-manager.
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-cm", Namespace: "default"},
		Spec:       ecv1alpha1.EtcdClusterSpec{TLS: &ecv1alpha1.TLSCertificate{Provider: string(certificate.CertManager)}},
	}

	err := ensureClusterTLS(t.Context(), ec, cli)
	// The cert-manager path will error because the fake client does not know
	// about Certificate CRDs, but the CA Secret must not be planted in either
	// branch.
	require.Error(t, err)
	s := &corev1.Secret{}
	getErr := cli.Get(t.Context(), client.ObjectKey{Name: getCASecretName(ec.Name), Namespace: ec.Namespace}, s)
	require.True(t, k8serrors.IsNotFound(getErr),
		"cert-manager cluster must not create an auto CA Secret")
}

// generateCertTestCA builds a throwaway self-signed CA certificate for the
// cert-manager controller tests below.
func generateCertTestCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-cm-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestEnsureClusterTLS_CertManagerMaterializesCASecret(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, ecv1alpha1.AddToScheme(scheme))
	require.NoError(t, certv1.AddToScheme(scheme))

	certPEM, _ := generateCertTestCA(t)

	const issuerName = "cm-test-issuer"
	const issuerSecret = "cm-test-issuer-ca"
	namespace := "default"

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ctx := context.Background()

	// Plant the cert-manager Issuer and the Secret it points at.
	require.NoError(t, cli.Create(ctx, &certv1.Issuer{
		TypeMeta:   metav1.TypeMeta{Kind: "Issuer"},
		ObjectMeta: metav1.ObjectMeta{Name: issuerName, Namespace: namespace},
		Spec: certv1.IssuerSpec{
			IssuerConfig: certv1.IssuerConfig{
				CA: &certv1.CAIssuer{SecretName: issuerSecret},
			},
		},
	}))
	require.NoError(t, cli.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: issuerSecret, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt":  certPEM,
			"tls.crt": certPEM,
		},
	}))
	// Plant one leaf Certificate CR referencing the Issuer so the cert-manager
	// provider's resolveClusterIssuerRef can find it.
	require.NoError(t, cli.Create(ctx, &certv1.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-cm-client-tls", Namespace: namespace},
		Spec: certv1.CertificateSpec{
			SecretName: "etcd-cm-client-tls",
			IssuerRef:  cmmeta.IssuerReference{Name: issuerName, Kind: "Issuer"},
		},
	}))

	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-cm", Namespace: namespace, UID: "uid-cm"},
		Spec: ecv1alpha1.EtcdClusterSpec{
			TLS: &ecv1alpha1.TLSCertificate{
				Provider: string(certificate.CertManager),
				ProviderCfg: ecv1alpha1.ProviderConfig{
					CertManagerCfg: &ecv1alpha1.ProviderCertManagerConfig{IssuerName: issuerName, IssuerKind: "Issuer"},
				},
			},
		},
	}

	require.NoError(t, ensureClusterTLS(ctx, ec, cli))

	// The cert-manager provider must have materialized the cluster trust-root
	// Secret with the Issuer CA under ca.crt and no ca.key.
	caSecret := &corev1.Secret{}
	require.NoError(t, cli.Get(ctx, client.ObjectKey{Name: getCASecretName(ec.Name), Namespace: ec.Namespace}, caSecret),
		"ensureClusterTLS must invoke EnsureCASecret for the cert-manager provider")
	assert.Equal(t, corev1.SecretTypeOpaque, caSecret.Type)
	assert.Equal(t, certPEM, caSecret.Data["ca.crt"])
	_, hasKey := caSecret.Data["ca.key"]
	assert.False(t, hasKey, "cert-manager trust-root Secret must not carry ca.key")
}

func TestApplyEtcdMemberCerts_NoOpForAuto(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-noop", Namespace: "default"},
		Spec:       ecv1alpha1.EtcdClusterSpec{TLS: &ecv1alpha1.TLSCertificate{Provider: string(certificate.Auto)}},
	}
	require.NoError(t, applyEtcdMemberCerts(t.Context(), ec, cli))
	s := &corev1.Secret{}
	err := cli.Get(t.Context(), client.ObjectKey{Name: getServerCertName(ec.Name), Namespace: ec.Namespace}, s)
	require.True(t, k8serrors.IsNotFound(err), "applyEtcdMemberCerts must not create Secrets for auto provider")
}

// ---------------------------------------------------------------------------
// buildClientTLSConfig uses the client Secret
// ---------------------------------------------------------------------------

func TestBuildClientTLSConfig_UsesClientSecret(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, ecv1alpha1.AddToScheme(scheme))
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-tls", Namespace: "default"},
		Spec:       ecv1alpha1.EtcdClusterSpec{TLS: &ecv1alpha1.TLSCertificate{Provider: string(certificate.Auto)}},
	}

	require.NoError(t, ensureClusterTLS(t.Context(), ec, cli))

	cfg, err := buildClientTLSConfig(t.Context(), ec, cli)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Certificates, 1)
	require.NotNil(t, cfg.RootCAs)
}

func TestBuildClientTLSConfig_FailsWhenClientSecretMissing(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, ecv1alpha1.AddToScheme(scheme))
	cli := fake.NewClientBuilder().WithScheme(scheme).Build()

	ec := &ecv1alpha1.EtcdCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "etcd-tls", Namespace: "default"},
		Spec:       ecv1alpha1.EtcdClusterSpec{TLS: &ecv1alpha1.TLSCertificate{Provider: string(certificate.Auto)}},
	}

	_, err := buildClientTLSConfig(t.Context(), ec, cli)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client certificate")
}
