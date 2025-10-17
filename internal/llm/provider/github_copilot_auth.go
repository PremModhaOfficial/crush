package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	githubCopilotClientID      = "Iv1.b507a08c87ecfe98"
	githubDeviceCodeURL        = "https://github.com/login/device/code"
	githubAccessTokenURL       = "https://github.com/login/oauth/access_token"
	githubCopilotTokenURL      = "https://api.github.com/copilot_internal/v2/token"
	githubCopilotUserAgent     = "GitHubCopilotChat/0.31.2"
	githubCopilotEditorVersion = "vscode/1.104.1"
	githubCopilotPluginVersion = "copilot-chat/0.31.2"
)

type GitHubDeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type GitHubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
}

type GitHubCopilotTokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	RefreshIn int64  `json:"refresh_in"`
	Endpoints struct {
		API string `json:"api"`
	} `json:"endpoints"`
}

type GitHubCopilotAuth struct {
	GitHubOAuthToken string
	CopilotAPIToken  string
	ExpiresAt        int64
	httpClient       *http.Client
	onTokenSave      func(string) error
}

func NewGitHubCopilotAuth(httpClient *http.Client) *GitHubCopilotAuth {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &GitHubCopilotAuth{
		httpClient:  httpClient,
		onTokenSave: nil,
	}
}

func (g *GitHubCopilotAuth) SetTokenSaveCallback(callback func(string) error) {
	g.onTokenSave = callback
}

func (g *GitHubCopilotAuth) InitiateDeviceFlow(ctx context.Context) (*GitHubDeviceCodeResponse, error) {
	reqBody := map[string]string{
		"client_id": githubCopilotClientID,
		"scope":     "read:user",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", githubDeviceCodeURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", githubCopilotUserAgent)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request device code: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var deviceResp GitHubDeviceCodeResponse
	if err := json.Unmarshal(respBody, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &deviceResp, nil
}

func (g *GitHubCopilotAuth) PollForAccessToken(ctx context.Context, deviceCode string, interval int) (string, error) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			reqBody := map[string]string{
				"client_id":   githubCopilotClientID,
				"device_code": deviceCode,
				"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			}

			body, err := json.Marshal(reqBody)
			if err != nil {
				return "", fmt.Errorf("failed to marshal request: %w", err)
			}

			req, err := http.NewRequestWithContext(ctx, "POST", githubAccessTokenURL, strings.NewReader(string(body)))
			if err != nil {
				return "", fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Accept", "application/json")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("User-Agent", githubCopilotUserAgent)

			resp, err := g.httpClient.Do(req)
			if err != nil {
				return "", fmt.Errorf("failed to poll for access token: %w", err)
			}

			respBody, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				return "", fmt.Errorf("failed to read response: %w", err)
			}

			var tokenResp GitHubAccessTokenResponse
			if err := json.Unmarshal(respBody, &tokenResp); err != nil {
				return "", fmt.Errorf("failed to unmarshal response: %w", err)
			}

			if tokenResp.Error != "" {
				if tokenResp.Error == "authorization_pending" {
					continue
				}
				if tokenResp.Error == "slow_down" {
					ticker.Reset(time.Duration(interval+5) * time.Second)
					continue
				}
				return "", fmt.Errorf("github oauth error: %s", tokenResp.Error)
			}

			if tokenResp.AccessToken != "" {
				g.GitHubOAuthToken = tokenResp.AccessToken
				return tokenResp.AccessToken, nil
			}
		}
	}
}

func (g *GitHubCopilotAuth) ExchangeForCopilotToken(ctx context.Context) error {
	if g.GitHubOAuthToken == "" {
		return fmt.Errorf("github oauth token not set")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", githubCopilotTokenURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.GitHubOAuthToken)
	req.Header.Set("User-Agent", githubCopilotUserAgent)
	req.Header.Set("Editor-Version", githubCopilotEditorVersion)
	req.Header.Set("Editor-Plugin-Version", githubCopilotPluginVersion)
	req.Header.Set("Copilot-Integration-Id", "vscode-chat")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to exchange for copilot token: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var copilotResp GitHubCopilotTokenResponse
	if err := json.Unmarshal(respBody, &copilotResp); err != nil {
		return fmt.Errorf("failed to unmarshal response: %w", err)
	}

	g.CopilotAPIToken = copilotResp.Token
	g.ExpiresAt = copilotResp.ExpiresAt

	return nil
}

func (g *GitHubCopilotAuth) PerformDeviceFlowAuth(ctx context.Context) error {
	deviceResp, err := g.InitiateDeviceFlow(ctx)
	if err != nil {
		return fmt.Errorf("failed to initiate device flow: %w", err)
	}

	fmt.Printf("\n🔐 GitHub Copilot Authentication Required\n\n")
	fmt.Printf("Please visit: %s\n", deviceResp.VerificationURI)
	fmt.Printf("And enter code: %s\n\n", deviceResp.UserCode)
	fmt.Printf("Waiting for authentication...\n")

	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(deviceResp.ExpiresIn)*time.Second)
	defer cancel()

	_, err = g.PollForAccessToken(pollCtx, deviceResp.DeviceCode, deviceResp.Interval)
	if err != nil {
		return fmt.Errorf("failed to obtain access token: %w", err)
	}

	if g.onTokenSave != nil && g.GitHubOAuthToken != "" {
		if err := g.onTokenSave(g.GitHubOAuthToken); err != nil {
			return fmt.Errorf("failed to save OAuth token: %w", err)
		}
	}

	fmt.Printf("✓ Successfully authenticated with GitHub!\n\n")
	return nil
}

func (g *GitHubCopilotAuth) GetValidToken(ctx context.Context) (string, error) {
	now := time.Now().Unix()

	if g.GitHubOAuthToken == "" {
		if err := g.PerformDeviceFlowAuth(ctx); err != nil {
			return "", fmt.Errorf("failed to authenticate with GitHub: %w", err)
		}
	}

	if g.CopilotAPIToken == "" || g.ExpiresAt <= now {
		if err := g.ExchangeForCopilotToken(ctx); err != nil {
			return "", fmt.Errorf("failed to refresh copilot token: %w", err)
		}
	}

	return g.CopilotAPIToken, nil
}

func (g *GitHubCopilotAuth) SetGitHubOAuthToken(token string) {
	g.GitHubOAuthToken = token
}
