// Package state manages the agent's on-disk identity: private key, certificate,
// pinned CA and enrollment metadata. The private key is generated locally
// (ECDSA P-256), written 0600 and never transmitted.
package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	KeyFile      = "agent.key"
	CertFile     = "agent.crt"
	CAFile       = "ca.crt"
	IdentityFile = "identity.json"
	JobCacheFile = "completed-jobs.json"
)

// Identity is the non-secret enrollment metadata.
type Identity struct {
	ServerID             string    `json:"serverId"`
	GatewayURL           string    `json:"gatewayUrl"`
	HeartbeatIntervalSec int       `json:"heartbeatIntervalSec,omitempty"`
	EnrolledAt           time.Time `json:"enrolledAt"`
	// CertRenewAfter is the latest value the gateway advertised (optional).
	CertRenewAfter *time.Time `json:"certRenewAfter,omitempty"`
}

// Dir is a state directory.
type Dir struct{ Path string }

// Ensure creates the directory with 0700 and tightens perms if it exists.
func (d Dir) Ensure() error {
	if err := os.MkdirAll(d.Path, 0o700); err != nil {
		return err
	}
	return os.Chmod(d.Path, 0o700)
}

func (d Dir) p(name string) string { return filepath.Join(d.Path, name) }

// WriteFileAtomic writes data to name via temp file + rename with the given mode.
func (d Dir) WriteFileAtomic(name string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(d.Path, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, d.p(name))
}

// ReadFile reads a file in the state dir.
func (d Dir) ReadFile(name string) ([]byte, error) { return os.ReadFile(d.p(name)) }

// FilePath returns the absolute path of a state file.
func (d Dir) FilePath(name string) string { return d.p(name) }

// GenerateKey creates a fresh ECDSA P-256 key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// EncodeKey PEM-encodes a private key (PKCS#8).
func EncodeKey(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKey decodes a PEM PKCS#8 / EC private key.
func ParseKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM key")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("key is not ECDSA")
		}
		return ek, nil
	}
	return x509.ParseECPrivateKey(blk.Bytes)
}

// CreateCSR builds a PEM CSR. Center ignores the subject and sets its own.
func CreateCSR(k *ecdsa.PrivateKey, hostname string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "ppanel-agent:" + hostname},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ParseCert parses the first PEM certificate in b.
func ParseCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate")
	}
	return x509.ParseCertificate(blk.Bytes)
}

// SaveKey writes the key 0600.
func (d Dir) SaveKey(k *ecdsa.PrivateKey) error {
	b, err := EncodeKey(k)
	if err != nil {
		return err
	}
	return d.WriteFileAtomic(KeyFile, b, 0o600)
}

// SaveIdentity writes identity.json (0600).
func (d Dir) SaveIdentity(id *Identity) error {
	b, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return d.WriteFileAtomic(IdentityFile, b, 0o600)
}

// LoadIdentity reads identity.json.
func (d Dir) LoadIdentity() (*Identity, error) {
	b, err := d.ReadFile(IdentityFile)
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("identity.json: %w", err)
	}
	if id.ServerID == "" || id.GatewayURL == "" {
		return nil, errors.New("identity.json: missing serverId/gatewayUrl")
	}
	return &id, nil
}

// Enrolled reports whether a complete identity exists.
func (d Dir) Enrolled() bool {
	for _, f := range []string{KeyFile, CertFile, CAFile, IdentityFile} {
		if _, err := os.Stat(d.p(f)); err != nil {
			return false
		}
	}
	return true
}

// LoadTLS returns the client keypair and pinned CA pool (no system roots).
func (d Dir) LoadTLS() (tls.Certificate, *x509.CertPool, *x509.Certificate, error) {
	kp, err := tls.LoadX509KeyPair(d.p(CertFile), d.p(KeyFile))
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("load keypair: %w", err)
	}
	leaf, err := x509.ParseCertificate(kp.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	kp.Leaf = leaf
	caPEM, err := d.ReadFile(CAFile)
	if err != nil {
		return tls.Certificate{}, nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, nil, errors.New("ca.crt: no certificates")
	}
	return kp, pool, leaf, nil
}

// CheckPerms verifies the dir is 0700 and key is 0600 (used by check-config).
func (d Dir) CheckPerms() error {
	st, err := os.Stat(d.Path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state dir %s has mode %o, want 0700", d.Path, st.Mode().Perm())
	}
	if kst, err := os.Stat(d.p(KeyFile)); err == nil && kst.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("key file has mode %o, want 0600", kst.Mode().Perm())
	}
	return nil
}

// RenewDue reports whether the certificate should be rotated: past
// renewAfter (if advertised) or past 2/3 of its lifetime.
func RenewDue(leaf *x509.Certificate, renewAfter *time.Time, now time.Time) bool {
	if renewAfter != nil && !renewAfter.IsZero() && !now.Before(*renewAfter) {
		return true
	}
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return !now.Before(leaf.NotBefore.Add(life * 2 / 3))
}
