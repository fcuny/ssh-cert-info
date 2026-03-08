package main

import (
	"fmt"
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
		checkCertificate(certPath)
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

func checkCertificate(certPath string) {
	fmt.Printf("Certificate: %s\n", certPath)

	certData, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Printf("  Error: Failed to read certificate file: %v\n", err)
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certData)
	if err != nil {
		fmt.Printf("  Error: Failed to parse certificate: %v\n", err)
		return
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		fmt.Printf("  Error: Not an SSH certificate\n")
		return
	}

	displayCertificateInfo(cert)
}

func displayCertificateInfo(cert *ssh.Certificate) {
	certType := "Unknown"
	switch cert.CertType {
	case ssh.UserCert:
		certType = "ssh-ed25519-cert-v01@openssh.com user certificate"
	case ssh.HostCert:
		certType = "ssh-ed25519-cert-v01@openssh.com host certificate"
	}
	fmt.Printf("  Type: %s\n", certType)

	fmt.Printf("  Public key: %s %s\n", cert.Key.Type(), cert.KeyId)

	fmt.Printf("  Signing CA: %s\n", cert.SignatureKey.Type())

	fmt.Printf("  Key ID: %s\n", cert.KeyId)

	fmt.Printf("  Serial: %d\n", cert.Serial)

	validFrom := time.Unix(int64(cert.ValidAfter), 0)
	validTo := time.Unix(int64(cert.ValidBefore), 0)

	fmt.Printf("  Valid from: %s\n", validFrom.Format("2006-01-02T15:04:05"))

	if cert.ValidBefore == ssh.CertTimeInfinity {
		fmt.Printf("  Valid to: forever\n")
		fmt.Println("  ✓ Certificate is currently valid")
	} else {
		fmt.Printf("  Valid to: %s\n", validTo.Format("2006-01-02T15:04:05"))
		checkCertificateExpiration(validTo)
	}

	if len(cert.ValidPrincipals) > 0 {
		fmt.Println("  Principals:")
		for _, principal := range cert.ValidPrincipals {
			fmt.Printf("    %s\n", principal)
		}
	}

	if len(cert.CriticalOptions) > 0 {
		fmt.Println("  Critical Options:")
		for key, value := range cert.CriticalOptions {
			if value == "" {
				fmt.Printf("    %s\n", key)
			} else {
				fmt.Printf("    %s %s\n", key, value)
			}
		}
	}

	if len(cert.Extensions) > 0 {
		fmt.Println("  Extensions:")
		for key, value := range cert.Extensions {
			if value == "" {
				fmt.Printf("    %s\n", key)
			} else {
				fmt.Printf("    %s %s\n", key, value)
			}
		}
	}
}

func checkCertificateExpiration(validTo time.Time) {
	now := time.Now()
	if validTo.Before(now) {
		fmt.Println("  ⚠️  WARNING: Certificate has EXPIRED!")
	} else {
		fmt.Println("  ✓ Certificate is currently valid")
	}
}
