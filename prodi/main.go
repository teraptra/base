package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	vault "github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	auth "github.com/teraptra/base/prodi/oidc"
)

var (
	sshID    = *flag.String("ssh_key", "id_ed25519_sk", "ssh identity file")
	authPath = *flag.String("auth_path", "ssh-user-ca", "auth path")
	authRole = *flag.String("auth_role", "ssh-user", "auth role")
	emerg    = *flag.Bool("emergency", false, "Request Emergency Creds")
)

func main() {
	ctx := context.Background()

	if emerg {
		sshID = fmt.Sprintf("%s-emerg", sshID)
	}
	//Load SSH Key
	publicKey, err := getPubKey(getSshPath(), sshID)
	if err != nil || publicKey == "" {
		log.Fatalf("failed to load pub key: %v", err)
	}

	//Vault Client
	client, err := newVaultClient(ctx)
	if err != nil {
		log.Fatal("vault client error: ", err)
	}

	//#sign public key
	s, err := signPublicKey(ctx, publicKey, client)
	if err != nil {
		log.Fatal("error signing public key: ", err)
	}

	//#Save cert somewhere
	if err := writeKey(s); err != nil {
		log.Fatal("failed to save cert: ", err)
	}

	//#update agents
	exec.Command("ssh-add", "-D").Start()
	exec.Command("ssh-add").Start()
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
		return "", errors.Wrap(err, "Unable to read public key file")
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	s.Split(bufio.ScanWords)
	s.Scan()
	s.Scan()
	if s.Err() != nil {
		return "", errors.Wrap(err, "error scanning pubfile")
	}
	return s.Text(), nil
}

func login(ctx context.Context, client *vault.Client) (*vault.Secret, error) {
	oidcAuth, err := auth.NewOIDCAuth()
	if err != nil {
		return nil, errors.Wrap(err, "unable to initialize auth method")
	}

	return client.Auth().Login(ctx, oidcAuth)
}

func newVaultClient(ctx context.Context) (*vault.Client, error) {
	client, err := vault.NewClient(vault.DefaultConfig())
	if err != nil {
		errors.Wrap(err, "unable to initialize Vault client")
	}

	authInfo, err := login(ctx, client)
	if err != nil {
		return nil, errors.Wrap(err, "login error")
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
	return client.SSHWithMountPoint(authPath).SignKeyWithContext(ctx, authRole, req)
}

func writeKey(s *vault.Secret) error {
	sn := s.Data["serial_number"]
	key := s.Data["signed_key"]
	fmt.Printf("key serial: %s\n", sn)
	return os.WriteFile(getSshPath()+"/"+sshID+"-cert.pub", []byte(key.(string)), os.FileMode(0644))
}
