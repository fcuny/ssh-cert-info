package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	sshDir, err := getSSHDirectory()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting SSH directory: %v\n", err)
		os.Exit(1)
	}

	certFiles, err := findCertificateFiles(sshDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading SSH directory %s: %v\n", sshDir, err)
		os.Exit(1)
	}

	if len(certFiles) == 0 {
		fmt.Printf("No SSH certificates found in %s\n", sshDir)
		return
	}

	fmt.Println("SSH Certificate Report")
	fmt.Println("======================")
	fmt.Println()

	for _, certPath := range certFiles {
		checkCertificate(os.Stdout, certPath)
		fmt.Println()
	}
}

func getSSHDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".ssh"), nil
}

func findCertificateFiles(sshDir string) ([]string, error) {
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil, err
	}

	var certFiles []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".pub") && strings.Contains(name, "-cert.pub") {
			certFiles = append(certFiles, filepath.Join(sshDir, name))
		}
	}

	return certFiles, nil
}

func checkCertificate(w io.Writer, certPath string) {
	fmt.Fprintf(w, "Certificate: %s\n", certPath)

	certData, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Fprintf(w, "  Error: Failed to read certificate file: %v\n", err)
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		fmt.Fprintf(w, "  Error: Failed to parse certificate: %v\n", err)
		return
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		fmt.Fprintf(w, "  Error: Not an SSH certificate\n")
		return
	}

	displayCertificateInfo(w, cert)
}

func displayCertificateInfo(w io.Writer, cert *ssh.Certificate) {
	kind := "unknown"
	switch cert.CertType {
	case ssh.UserCert:
		kind = "user"
	case ssh.HostCert:
		kind = "host"
	}
	fmt.Fprintf(w, "  Type: %s %s certificate\n", cert.Type(), kind)

	fmt.Fprintf(w, "  Public key: %s %s\n", cert.Key.Type(), cert.KeyId)

	fmt.Fprintf(w, "  Signing CA: %s\n", cert.SignatureKey.Type())

	fmt.Fprintf(w, "  Key ID: %s\n", cert.KeyId)

	fmt.Fprintf(w, "  Serial: %d\n", cert.Serial)

	validFrom := time.Unix(int64(cert.ValidAfter), 0)
	validTo := time.Unix(int64(cert.ValidBefore), 0)

	fmt.Fprintf(w, "  Valid from: %s\n", validFrom.Format("2006-01-02T15:04:05"))

	if cert.ValidBefore == ssh.CertTimeInfinity {
		fmt.Fprintf(w, "  Valid to: forever\n")
		fmt.Fprintln(w, "  ✓ Certificate is currently valid")
	} else {
		fmt.Fprintf(w, "  Valid to: %s\n", validTo.Format("2006-01-02T15:04:05"))
		checkCertificateExpiration(w, validTo)
	}

	if len(cert.ValidPrincipals) > 0 {
		fmt.Fprintln(w, "  Principals:")
		for _, principal := range cert.ValidPrincipals {
			fmt.Fprintf(w, "    %s\n", principal)
		}
	}

	if len(cert.CriticalOptions) > 0 {
		fmt.Fprintln(w, "  Critical Options:")
		for key, value := range cert.CriticalOptions {
			if value == "" {
				fmt.Fprintf(w, "    %s\n", key)
			} else {
				fmt.Fprintf(w, "    %s %s\n", key, value)
			}
		}
	}

	if len(cert.Extensions) > 0 {
		fmt.Fprintln(w, "  Extensions:")
		for key, value := range cert.Extensions {
			if value == "" {
				fmt.Fprintf(w, "    %s\n", key)
			} else {
				fmt.Fprintf(w, "    %s %s\n", key, value)
			}
		}
	}
}

func checkCertificateExpiration(w io.Writer, validTo time.Time) {
	now := time.Now()
	if validTo.Before(now) {
		fmt.Fprintln(w, "  ⚠️  WARNING: Certificate has EXPIRED!")
	} else {
		fmt.Fprintln(w, "  ✓ Certificate is currently valid")
	}
}
