// Package sshkeys implements the P10 agent side of the central SSH gateway
// (docs/P10_SSH_CONTRACT.md §2): the typed job `ssh.keys.sync`, which installs
// PUBLIC keys into a managed block of ~user/.ssh/authorized_keys, and the
// `ssh` host facts (host key fingerprints + sshd port) used by the Center to
// cross-check the host key it sees over TCP.
//
// The agent never receives, reads or handles private key material: params
// carry public keys only, and a "public key" line that is anything else is
// refused (SSH_KEY_INVALID). There is no shell, and nothing here starts,
// stops or reconfigures sshd.
package sshkeys

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Key types accepted in ssh.keys.sync params (contract §2).
var syncKeyTypes = map[string]bool{
	"ssh-ed25519":         true,
	"ecdsa-sha2-nistp256": true,
	"ssh-rsa":             true,
}

// Host key types recognised in /etc/ssh/ssh_host_*_key.pub (facts only).
var hostKeyTypes = map[string]bool{
	"ssh-ed25519":         true,
	"ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true,
	"ssh-rsa":             true,
}

// MinRSABits mirrors the Center's import rule (RSA < 3072 → SSH_KEY_UNSUPPORTED).
const MinRSABits = 3072

// MaxPublicKeyLine bounds one public key line (a 16384-bit RSA key is ~2.8 KiB).
const MaxPublicKeyLine = 8192

// PublicKey is a parsed OpenSSH one-line public key.
type PublicKey struct {
	Type    string // e.g. ssh-ed25519
	Base64  string // the key blob exactly as given (canonical padded base64)
	Blob    []byte
	Comment string
}

// Fingerprint returns the OpenSSH SHA256 fingerprint: "SHA256:" + unpadded
// standard base64 of sha256(blob).
func Fingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Fingerprint of the parsed key.
func (k *PublicKey) Fingerprint() string { return Fingerprint(k.Blob) }

// ParsePublicKey strictly parses "<type> <base64>[ <comment>]" with the given
// allowed types. It refuses options (anything before the type), control
// characters (newline injection), non-canonical base64, a blob whose inner
// type differs from the stated type, and malformed key material.
func ParsePublicKey(line string, allowed map[string]bool) (*PublicKey, error) {
	return parsePublicKey(line, allowed, MinRSABits)
}

func parsePublicKey(line string, allowed map[string]bool, minRSA int) (*PublicKey, error) {
	if line == "" || len(line) > MaxPublicKeyLine {
		return nil, errors.New("public key must be 1..8192 bytes")
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c < 0x20 || c == 0x7f || c >= 0x80 {
			return nil, errors.New("public key must be one line of printable ASCII")
		}
	}
	fields := strings.SplitN(line, " ", 3)
	if len(fields) < 2 {
		return nil, errors.New("public key must be '<type> <base64> [comment]'")
	}
	typ, b64 := fields[0], fields[1]
	if !allowed[typ] {
		// also catches an options prefix such as `command="..." ssh-ed25519 AAAA`
		return nil, fmt.Errorf("key type %q is not allowed", truncate(typ, 40))
	}
	comment := ""
	if len(fields) == 3 {
		comment = fields[2]
		if strings.TrimSpace(comment) != comment || comment == "" {
			return nil, errors.New("public key comment must not have leading/trailing spaces")
		}
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(blob) == 0 || base64.StdEncoding.EncodeToString(blob) != b64 {
		return nil, errors.New("public key blob is not canonical base64")
	}
	if err := checkBlob(typ, blob, minRSA); err != nil {
		return nil, err
	}
	return &PublicKey{Type: typ, Base64: b64, Blob: blob, Comment: comment}, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// wire is a reader of the SSH wire format (RFC 4251 string / mpint).
type wire struct{ b []byte }

func (w *wire) str() ([]byte, bool) {
	if len(w.b) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(w.b)
	if uint64(n) > uint64(len(w.b)-4) {
		return nil, false
	}
	s := w.b[4 : 4+n]
	w.b = w.b[4+n:]
	return s, true
}

// checkBlob validates the key blob structure for the stated type.
func checkBlob(typ string, blob []byte, minRSA int) error {
	w := &wire{b: blob}
	inner, ok := w.str()
	if !ok || string(inner) != typ {
		return errors.New("key blob type does not match the stated key type")
	}
	switch {
	case typ == "ssh-ed25519":
		pk, ok := w.str()
		if !ok || len(pk) != 32 {
			return errors.New("malformed ssh-ed25519 key")
		}
	case strings.HasPrefix(typ, "ecdsa-sha2-"):
		curve, ok1 := w.str()
		q, ok2 := w.str()
		if !ok1 || !ok2 || "ecdsa-sha2-"+string(curve) != typ {
			return errors.New("malformed ecdsa key")
		}
		want := map[string]int{"nistp256": 65, "nistp384": 97, "nistp521": 133}[string(curve)]
		if len(q) != want || q[0] != 0x04 {
			return errors.New("malformed ecdsa point (uncompressed point expected)")
		}
	case typ == "ssh-rsa":
		e, ok1 := w.str()
		n, ok2 := w.str()
		if !ok1 || !ok2 || len(e) == 0 || len(e) > 8 || len(n) == 0 || e[0]&0x80 != 0 || n[0]&0x80 != 0 {
			return errors.New("malformed ssh-rsa key")
		}
		if bits := new(big.Int).SetBytes(n).BitLen(); bits < minRSA || bits > 16384 {
			return fmt.Errorf("ssh-rsa modulus of %d bits is outside %d..16384", bits, minRSA)
		}
		if new(big.Int).SetBytes(e).Cmp(big.NewInt(3)) < 0 {
			return errors.New("malformed ssh-rsa exponent")
		}
	default:
		return errors.New("unsupported key type")
	}
	if len(w.b) != 0 {
		return errors.New("trailing data in key blob")
	}
	return nil
}
