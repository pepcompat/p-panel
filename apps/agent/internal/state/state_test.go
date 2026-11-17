package state

import (
	"crypto/x509"
	"os"
	"testing"
	"time"
)

func TestKeyCSRAndPerms(t *testing.T) {
	d := Dir{Path: t.TempDir() + "/s"}
	if err := d.Ensure(); err != nil {
		t.Fatal(err)
	}
	k, _ := GenerateKey()
	if err := d.SaveKey(k); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(d.FilePath(KeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	if err := d.CheckPerms(); err != nil {
		t.Fatal(err)
	}
	b, _ := d.ReadFile(KeyFile)
	k2, err := ParseKey(b)
	if err != nil || !k2.Equal(k) {
		t.Fatal("key round trip")
	}
	csr, err := CreateCSR(k, "h")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCert(csr); err == nil {
		t.Fatal("csr is not a cert")
	}
	os.Chmod(d.Path, 0o755)
	if err := d.CheckPerms(); err == nil {
		t.Fatal("loose dir perms must fail")
	}
}

func TestRenewDue(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour)}
	if RenewDue(leaf, nil, now) {
		t.Fatal("1/3 elapsed: not due")
	}
	if !RenewDue(leaf, nil, now.Add(time.Hour+time.Minute)) {
		t.Fatal("past 2/3: due")
	}
	ra := now.Add(-time.Second)
	if !RenewDue(leaf, &ra, now) {
		t.Fatal("past certRenewAfter: due")
	}
}
