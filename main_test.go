package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// runMainEnv makes the test binary behave as the ssh-cert-info CLI, so tests
// can observe real stdout, stderr and exit codes.
const runMainEnv = "SSH_CERT_INFO_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	return signer
}

// newCertificate returns an ed25519 user certificate, valid from an hour ago
// until a day from now and signed by a fresh CA. modify, when set, changes
// the certificate before it is signed.
func newCertificate(t *testing.T, modify func(*ssh.Certificate)) *ssh.Certificate {
	t.Helper()

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             newSigner(t).PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "alice@example.com",
		Serial:          42,
		ValidPrincipals: []string{"alice", "admin"},
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(now.Add(24 * time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{"force-command": "/usr/bin/true"},
			Extensions:      map[string]string{"permit-pty": "", "permit-port-forwarding": ""},
		},
	}
	if modify != nil {
		modify(cert)
	}
	if err := cert.SignCert(rand.Reader, newSigner(t)); err != nil {
		t.Fatalf("signing certificate: %v", err)
	}
	return cert
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func formatCertTime(ts uint64) string {
	return time.Unix(int64(ts), 0).Format("2006-01-02T15:04:05")
}

func TestFindCertificateFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"id_ed25519",
		"id_ed25519.pub",
		"id_ed25519-cert.pub",
		"host-cert.pub",
		"known_hosts",
		"notes-cert.pub.bak",
	} {
		writeFile(t, filepath.Join(dir, name), nil)
	}
	if err := os.Mkdir(filepath.Join(dir, "dir-cert.pub"), 0o700); err != nil {
		t.Fatalf("creating directory: %v", err)
	}

	got, err := findCertificateFiles(dir)
	if err != nil {
		t.Fatalf("findCertificateFiles() error = %v", err)
	}
	want := []string{
		filepath.Join(dir, "host-cert.pub"),
		filepath.Join(dir, "id_ed25519-cert.pub"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("findCertificateFiles() = %q, want %q", got, want)
	}
}

func TestFindCertificateFilesMissingDirectory(t *testing.T) {
	_, err := findCertificateFiles(filepath.Join(t.TempDir(), "missing"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("findCertificateFiles() error = %v, want %v", err, os.ErrNotExist)
	}
}

func TestCheckCertificate(t *testing.T) {
	valid := newCertificate(t, nil)
	host := newCertificate(t, func(c *ssh.Certificate) { c.CertType = ssh.HostCert })
	expired := newCertificate(t, func(c *ssh.Certificate) {
		c.ValidBefore = uint64(time.Now().Add(-time.Hour).Unix())
	})
	forever := newCertificate(t, func(c *ssh.Certificate) { c.ValidBefore = ssh.CertTimeInfinity })
	notYetValid := newCertificate(t, func(c *ssh.Certificate) {
		c.ValidAfter = uint64(time.Now().Add(time.Hour).Unix())
	})

	tests := []struct {
		name    string
		data    []byte
		want    []string
		notWant []string
	}{
		{
			name: "valid user certificate",
			data: ssh.MarshalAuthorizedKey(valid),
			want: []string{
				"  Type: ssh-ed25519-cert-v01@openssh.com user certificate\n",
				"  Public key: ssh-ed25519 " + ssh.FingerprintSHA256(valid.Key) + "\n",
				"  Signing CA: ssh-ed25519\n",
				"  Key ID: alice@example.com\n",
				"  Serial: 42\n",
				"  Valid from: " + formatCertTime(valid.ValidAfter) + "\n",
				"  Valid to: " + formatCertTime(valid.ValidBefore) + "\n",
				"  ✓ Certificate is currently valid\n",
				"  Principals:\n    alice\n    admin\n",
				"  Critical Options:\n    force-command /usr/bin/true\n",
				"  Extensions:\n",
				"    permit-pty\n",
				"    permit-port-forwarding\n",
			},
			notWant: []string{"WARNING", "Error"},
		},
		{
			name: "host certificate",
			data: ssh.MarshalAuthorizedKey(host),
			want: []string{"  Type: ssh-ed25519-cert-v01@openssh.com host certificate\n"},
		},
		{
			name:    "expired certificate",
			data:    ssh.MarshalAuthorizedKey(expired),
			want:    []string{"  ⚠️  WARNING: Certificate has EXPIRED!\n"},
			notWant: []string{"currently valid"},
		},
		{
			name:    "not yet valid certificate",
			data:    ssh.MarshalAuthorizedKey(notYetValid),
			want:    []string{"  ⚠️  WARNING: Certificate is not yet valid!\n"},
			notWant: []string{"currently valid", "EXPIRED"},
		},
		{
			name: "certificate without expiry",
			data: ssh.MarshalAuthorizedKey(forever),
			want: []string{
				"  Valid to: forever\n",
				"  ✓ Certificate is currently valid\n",
			},
		},
		{
			name:    "plain public key",
			data:    ssh.MarshalAuthorizedKey(newSigner(t).PublicKey()),
			want:    []string{"  Error: Not an SSH certificate\n"},
			notWant: []string{"Key ID"},
		},
		{
			name: "unparseable file",
			data: []byte("not a key\n"),
			want: []string{"  Error: Failed to parse certificate: "},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "id_ed25519-cert.pub")
			writeFile(t, path, tt.data)

			var out bytes.Buffer
			checkCertificate(&out, path)
			got := out.String()

			if !strings.HasPrefix(got, "Certificate: "+path+"\n") {
				t.Errorf("output does not start with the certificate path:\n%s", got)
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("output does not contain %q:\n%s", want, got)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Errorf("output contains %q:\n%s", notWant, got)
				}
			}
		})
	}
}

func TestCertificateType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA key: %v", err)
	}

	tests := []struct {
		name     string
		key      any
		certType uint32
		want     string
	}{
		{name: "ed25519 user", key: nil, certType: ssh.UserCert, want: "ssh-ed25519-cert-v01@openssh.com user certificate"},
		{name: "RSA user", key: &rsaKey.PublicKey, certType: ssh.UserCert, want: "ssh-rsa-cert-v01@openssh.com user certificate"},
		{name: "ECDSA host", key: &ecdsaKey.PublicKey, certType: ssh.HostCert, want: "ecdsa-sha2-nistp256-cert-v01@openssh.com host certificate"},
		{name: "unknown kind", key: nil, certType: 3, want: "ssh-ed25519-cert-v01@openssh.com unknown certificate"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := newCertificate(t, func(c *ssh.Certificate) {
				c.CertType = tt.certType
				if tt.key != nil {
					pub, err := ssh.NewPublicKey(tt.key)
					if err != nil {
						t.Fatalf("converting public key: %v", err)
					}
					c.Key = pub
				}
			})

			var out bytes.Buffer
			displayCertificateInfo(&out, cert)
			if want := "  Type: " + tt.want + "\n"; !strings.Contains(out.String(), want) {
				t.Errorf("output does not contain %q:\n%s", want, out.String())
			}
		})
	}
}

func TestCheckCertificateMissingFile(t *testing.T) {
	var out bytes.Buffer
	checkCertificate(&out, filepath.Join(t.TempDir(), "missing-cert.pub"))

	want := "  Error: Failed to read certificate file: "
	if !strings.Contains(out.String(), want) {
		t.Errorf("output does not contain %q:\n%s", want, out.String())
	}
}

func TestCheckCertificateValidity(t *testing.T) {
	const (
		valid       = "  ✓ Certificate is currently valid\n"
		expired     = "  ⚠️  WARNING: Certificate has EXPIRED!\n"
		notYetValid = "  ⚠️  WARNING: Certificate is not yet valid!\n"
	)
	now := time.Unix(1_800_000_000, 0)
	unixNow := uint64(now.Unix())

	tests := []struct {
		name        string
		validAfter  uint64
		validBefore uint64
		want        string
	}{
		{name: "within the window", validAfter: unixNow - 60, validBefore: unixNow + 60, want: valid},
		{name: "starts now", validAfter: unixNow, validBefore: unixNow + 60, want: valid},
		{name: "ends now", validAfter: unixNow - 60, validBefore: unixNow, want: expired},
		{name: "ended", validAfter: unixNow - 120, validBefore: unixNow - 60, want: expired},
		{name: "starts later", validAfter: unixNow + 60, validBefore: unixNow + 120, want: notYetValid},
		{name: "no bounds", validAfter: 0, validBefore: ssh.CertTimeInfinity, want: valid},
		{name: "no expiry but starts later", validAfter: unixNow + 60, validBefore: ssh.CertTimeInfinity, want: notYetValid},
		{name: "expiry past the int64 range", validAfter: 0, validBefore: ssh.CertTimeInfinity - 1, want: valid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &ssh.Certificate{ValidAfter: tt.validAfter, ValidBefore: tt.validBefore}

			var out bytes.Buffer
			checkCertificateValidity(&out, cert, now)
			if got := out.String(); got != tt.want {
				t.Errorf("checkCertificateValidity() = %q, want %q", got, tt.want)
			}
		})
	}
}

// runCLI runs the CLI with home as its home directory.
func runCLI(t *testing.T, home string) (stdout, stderr string, exitCode int) {
	t.Helper()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locating test binary: %v", err)
	}
	cmd := exec.Command(executable)
	cmd.Env = append(os.Environ(), runMainEnv+"=1", "HOME="+home)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("running CLI: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), cmd.ProcessState.ExitCode()
}

func TestCLI(t *testing.T) {
	t.Run("missing ssh directory", func(t *testing.T) {
		home := t.TempDir()

		stdout, stderr, code := runCLI(t, home)
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
		if want := "Error reading SSH directory " + filepath.Join(home, ".ssh"); !strings.Contains(stderr, want) {
			t.Errorf("stderr = %q, want it to contain %q", stderr, want)
		}
	})

	t.Run("no certificates", func(t *testing.T) {
		home := t.TempDir()
		sshDir := filepath.Join(home, ".ssh")
		if err := os.Mkdir(sshDir, 0o700); err != nil {
			t.Fatalf("creating %s: %v", sshDir, err)
		}

		stdout, stderr, code := runCLI(t, home)
		if code != 0 {
			t.Errorf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		if want := "No SSH certificates found in " + sshDir + "\n"; stdout != want {
			t.Errorf("stdout = %q, want %q", stdout, want)
		}
	})

	t.Run("one certificate", func(t *testing.T) {
		home := t.TempDir()
		sshDir := filepath.Join(home, ".ssh")
		if err := os.Mkdir(sshDir, 0o700); err != nil {
			t.Fatalf("creating %s: %v", sshDir, err)
		}
		certPath := filepath.Join(sshDir, "id_ed25519-cert.pub")
		writeFile(t, certPath, ssh.MarshalAuthorizedKey(newCertificate(t, nil)))

		stdout, stderr, code := runCLI(t, home)
		if code != 0 {
			t.Errorf("exit code = %d, want 0 (stderr: %q)", code, stderr)
		}
		for _, want := range []string{
			"SSH Certificate Report\n======================\n\n",
			"Certificate: " + certPath + "\n",
			"  Key ID: alice@example.com\n",
		} {
			if !strings.Contains(stdout, want) {
				t.Errorf("stdout does not contain %q:\n%s", want, stdout)
			}
		}
	})
}
