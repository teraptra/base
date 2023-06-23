package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/hashicorp/vault/api"
	"golang.org/x/sync/errgroup"
)

var _ api.AuthMethod = (*OIDCAuth)(nil)

const (
	defaultMountPath = "oidc"
	defaultRedirect  = "http://localhost:8250/oidc/callback"
)

type OIDCAuth struct {
	mountPath string
	roleName  string
}

type ctoken struct {
	state string
	code  string
	nonce string
}

type LoginOption func(a *OIDCAuth) error

func startListener(ctx context.Context, tc chan ctoken) error {
	srv := http.Server{
		Addr: "localhost:8250",
	}
	ec := make(chan error, 1)
	callHandler := func(w http.ResponseWriter, req *http.Request) {
		ct := ctoken{
			state: req.URL.Query().Get("state"),
			code:  req.URL.Query().Get("code"),
			nonce: req.URL.Query().Get("nonce"),
		}
		if ct.state == "" {
			ec <- errors.New("missing auth state")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "Got token.")

		defer srv.Shutdown(ctx)
		tc <- ct
	}
	http.HandleFunc("/oidc/callback", callHandler)

	err := srv.ListenAndServe()
	if err != http.ErrServerClosed {
		return err
	}
	select {
	case err := <-ec:
		return err
	default:
	}
	return nil
}

func (a *OIDCAuth) requestAuthToken(ctx context.Context, client *api.Client, st *api.Secret, ct ctoken) (*api.Secret, error) {
	path := fmt.Sprintf("v1/auth/oidc/%s/callback", a.mountPath)
	r := client.NewRequest("GET", path)
	r.Params.Add("state", ct.state)
	r.Params.Add("code", ct.code)
	if ct.nonce != "" {
		r.Params.Add("nonce", ct.nonce)
	}
	resp, err := client.RawRequestWithContext(ctx, r)
	defer resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to get auth uri: %w", err)
	}
	if err := resp.DecodeJSON(st); err != nil {
		return nil, fmt.Errorf("failed to decode response url: %w", err)
	}
	if st.Auth.ClientToken == "" {
		return nil, errors.New("empty client token")
	}

	return st, nil
}

func (a *OIDCAuth) doCallout(ctx context.Context, client *api.Client, loginData map[string]any) (*api.Secret, error) {
	//get auth url
	secret, err := a.requestAuth(ctx, client, loginData)
	if err != nil {
		return nil, fmt.Errorf("unable to get auth url: %w", err)
	}

	tc := make(chan ctoken, 1)
	//start local responder
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return startListener(gctx, tc)
	})

	authURI, ok := secret.Data["auth_url"].(string)
	if !ok {
		return nil, errors.New("not string")
	}

	//open browser
	if err := openbrowser(authURI); err != nil {
		return nil, fmt.Errorf("failed in browser callout: %w", err)
	}

	//wait for Response
	if err := g.Wait(); err != nil {
		return nil, err
	}
	tctx, cncl := context.WithTimeout(ctx, time.Second*5)
	defer cncl()
	var tok ctoken
	select {
	case <-tctx.Done():
		return nil, fmt.Errorf("timeout exceeded: %w", tctx.Err())
	case tok = <-tc:
	}

	rt, err := a.requestAuthToken(ctx, client, secret, tok)
	if err != nil {
		return nil, fmt.Errorf("Failed to get final token: %w", err)
	}

	return rt, nil
}

type Response struct {
	LeaseId       string `json:"lease_id"`
	Renewable     bool
	LeaseDuration int `json:"lease_duration"`
	Data          map[string]string
	WrapInfo      any `json:"wrap_info"`
	Warnings      any
	Auth          any
	RequestId     string `json:"request_id"`
}

func openbrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}

func (a *OIDCAuth) requestAuth(ctx context.Context, client *api.Client, loginData map[string]any) (*api.Secret, error) {
	path := fmt.Sprintf("v1/auth/oidc/%s/auth_url", a.mountPath)
	r := client.NewRequest("POST", path)
	r.SetJSONBody(loginData)
	resp, err := client.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth uri: %w", err)
	}
	defer resp.Body.Close()
	body := api.Secret{}
	if err := resp.DecodeJSON(&body); err != nil {
		return nil, fmt.Errorf("failed to decode response url: %w", err)
	}
	if body.Data["auth_url"] == nil {
		return nil, errors.New("missing auth URL")
	}

	return &body, nil
}

func (a *OIDCAuth) Login(ctx context.Context, client *api.Client) (*api.Secret, error) {
	if ctx == nil {
		return nil, errors.New("missing context")
	}

	loginData := map[string]any{
		"role":         a.roleName,
		"redirect_uri": defaultRedirect,
	}

	cr, err := a.doCallout(ctx, client, loginData)
	if err != nil {
		return nil, err
	}

	return cr, nil
}

func NewOIDCAuth(opts ...LoginOption) (*OIDCAuth, error) {
	a := &OIDCAuth{
		mountPath: defaultMountPath,
		roleName:  "",
	}
	for _, opt := range opts {
		// Call the option giving the instantiated
		// *AppRoleAuth as the argument
		err := opt(a)
		if err != nil {
			return nil, fmt.Errorf("error with login option: %w", err)
		}
	}
	return a, nil
}
