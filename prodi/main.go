package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	vault "github.com/hashicorp/vault/api"
	auth "oidc"
	"golang.org/x/exp/slog"
)

var (
	sshID = flag.String("ssh_key", "id_ed25519_sk", "ssh identity file")
	authPath  = flag.String("auth_path", "ssh-user-ca", "auth path")
	authRole  = flag.String("auth_role", "ssh-user", "auth role")
	emerg     = flag.Bool("emergency", false, "Request Emergency Creds")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := doStuff(ctx); err != nil {
		slog.Error("failed to get prod cert: ", err)
		os.Exit(-1)
	}
}

// doStuff implements the basic business logic
func doStuff(ctx context.Context) error {
	if *emerg {
		*sshID = fmt.Sprintf("%s-emerg", *sshID)
		*authRole = "ssh-emerg"
	}
	// Load SSH Key
	publicKey, err := getPubKey(getSshPath(), *sshID)
	if err != nil || publicKey == "" {
		return fmt.Errorf("failed to load pub key: %w", err)
	}

	// Vault Client
	client, err := newVaultClient(ctx)
	if err != nil {
		return fmt.Errorf("vault client error: %w", err)
	}

	//#sign public key
	s, err := signPublicKey(ctx, publicKey, client)
	if err != nil {
		return fmt.Errorf("error signing public key: %w", err)
	}

	//#Save cert somewhere
	if err := writeKey(s); err != nil {
		return fmt.Errorf("failed to save cert: %w", err)
	}

	//#update agents
	if err := exec.Command("ssh-add", "-D").Start(); err != nil {
		return fmt.Errorf("failed to update ssh agent: %w", err)
	}
	if err := exec.Command("ssh-add").Start(); err != nil {
		return fmt.Errorf("failed to update ssh agent: %w", err)
	}

	return nil
}

func getSshPath() string {
	hd, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	return fmt.Sprintf("%s/.ssh", hd)
}

func getPubKey(path, file string) (string, error) {
	f, err := os.Open(path + "/" + file + ".pub")
	if err != nil {
		return "", fmt.Errorf("unable to read public key file: %w", err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Split(bufio.ScanWords)
	s.Scan()
	s.Scan()
	if s.Err() != nil {
		return "", fmt.Errorf("error scanning pubfile: %w", err)
	}
	return s.Text(), nil
}

func login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	oidcAuth, err := auth.NewOIDCAuth()
	if err != nil {
		return nil, fmt.Errorf("unable to initialize auth method: %w", err)
	}

	return client.Auth().Login(ctx, oidcAuth)
}

func newVaultClient(ctx context.Context) (*vault.Client, error) {
	client, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Vault client: %w", err)
	}

	authInfo, err := login(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("login error: %w", err)
	}
	if authInfo == nil {
		return nil, errors.New("empty auth info")
	}

	return client, nil
}

func signPublicKey(ctx context.Context, publicKey string, client *vault.Client) (*vault.Secret, error) {
	req := map[string]any{
		"public_key": publicKey,
	}
	return client.SSHWithMountPoint(*authPath).SignKeyWithContext(ctx, *authRole, req)
}

func writeKey(s *vault.Secret) error {
	sn := s.Data["serial_number"]
	key := s.Data["signed_key"]
	fmt.Printf("key serial: %s\n", sn)
	return os.WriteFile(getSshPath()+"/"+*sshID+"-cert.pub", []byte(key.(string)), os.FileMode(0o644))
}
