# GitHub Copilot Integration Guide

## Overview

GitHub Copilot is now fully integrated into Crush as a provider. This integration uses GitHub's OAuth device flow for authentication and supports multiple models through the Copilot API.

## Implementation Files

### Core Provider Implementation
- `internal/llm/provider/github_copilot.go` - Main provider client implementation
- `internal/llm/provider/github_copilot_auth.go` - OAuth authentication and token management
- `internal/llm/provider/provider.go` - Factory integration (lines 208-212)

### Configuration
- `internal/config/config.go` - Schema definition (line 77)
- `internal/config/load.go` - Provider validation (line 285)
- `schema.json` - Generated JSON schema with github-copilot enum

### Documentation
- `CRUSH.md` - Developer documentation with configuration example
- `github-copilot-example.json` - Example configuration file

## Usage

### Configuration

Add to your `crush.json`:

```json
{
  "$schema": "https://charm.land/crush.json",
  "providers": {
    "github-copilot": {
      "id": "github-copilot",
      "name": "GitHub Copilot",
      "type": "github-copilot",
      "base_url": "https://api.githubcopilot.com",
      "models": [
        {
          "id": "gpt-4o",
          "name": "GPT-4o",
          "context_window": 128000,
          "default_max_tokens": 4096
        },
        {
          "id": "claude-opus-4",
          "name": "Claude Opus 4",
          "context_window": 200000,
          "default_max_tokens": 8192
        },
        {
          "id": "o1",
          "name": "OpenAI o1",
          "context_window": 128000,
          "default_max_tokens": 8192,
          "can_reason": true
        }
      ]
    }
  }
}
```

### Authentication Flow

The authentication process is fully automated and triggered on first use:

1. **First Run**: When you first start Crush with GitHub Copilot configured (without an `api_key` in config), Crush will automatically initiate the OAuth flow when you send your first message.

2. **Interactive Prompt**: You'll see output similar to:
   ```
   🔐 GitHub Copilot Authentication Required

   Please visit: https://github.com/login/device
   And enter code: ABCD-1234

   Waiting for authentication...
   ```

3. **Browser Authorization**: 
   - Open the displayed URL in your browser
   - Enter the provided device code
   - Authorize Crush to access GitHub Copilot

4. **Automatic Token Persistence**: Once authorized:
   - OAuth token is automatically saved to your `crush.json` config file as `api_key`
   - OAuth token is exchanged for a Copilot API token
   - API tokens are automatically refreshed (they expire after 1 hour)

5. **Subsequent Sessions**: 
   - The saved OAuth token is loaded from config
   - No re-authentication needed unless token is revoked
   - API tokens refresh automatically as needed

### Requirements

- Active GitHub Copilot Pro+ subscription
- Internet connection for initial OAuth flow
- Browser access for one-time authorization (only on first run)

## Implementation Details

### Authentication Architecture

The `GitHubCopilotAuth` struct manages the complete OAuth flow:

```go
type GitHubCopilotAuth struct {
    GitHubOAuthToken string
    CopilotAPIToken  string
    ExpiresAt        int64
    httpClient       *http.Client
    onTokenSave      func(string) error
}
```

Key methods:
- `PerformDeviceFlowAuth(ctx)` - Initiates OAuth device flow and displays instructions to user
- `GetValidToken(ctx)` - Returns valid Copilot API token, automatically triggering auth flow if needed
- `ExchangeForCopilotToken(ctx)` - Exchanges OAuth token for Copilot API token
- `SetTokenSaveCallback(func)` - Sets callback to persist OAuth token to config file

### API Integration

The provider uses OpenAI's SDK with custom middleware to inject required headers:

```go
func createGitHubCopilotMiddleware(auth *GitHubCopilotAuth) option.Middleware {
    return func(req *http.Request, next option.MiddlewareNext) (*http.Response, error) {
        token, err := auth.GetValidToken(req.Context())
        if err != nil {
            return nil, fmt.Errorf("failed to get valid copilot token: %w", err)
        }
        
        req.Header.Set("Authorization", "Bearer "+token)
        req.Header.Set("User-Agent", githubCopilotUserAgent)
        req.Header.Set("Editor-Version", githubCopilotEditorVersion)
        req.Header.Set("Editor-Plugin-Version", githubCopilotPluginVersion)
        req.Header.Set("Copilot-Integration-Id", "vscode-chat")
        // ... more headers
        
        return next(req)
    }
}
```

### Token Management

- **OAuth Token**: 
  - Stored persistently in `crush.json` as `api_key`
  - Used to obtain short-lived Copilot API tokens
  - Persists across application restarts
  - Can be revoked via GitHub settings
  
- **Copilot API Token**: 
  - Short-lived (1 hour expiry)
  - Stored in memory only
  - Automatically refreshed using OAuth token when expired
  - Used for actual API requests
  
- **Automatic Flow**:
  - First run: Triggers device flow authentication
  - OAuth token saved to config automatically
  - Subsequent runs: OAuth token loaded from config
  - API token refreshed automatically as needed
  
- **Error Handling**: 
  - Automatic re-authentication on 401 errors
  - Comprehensive error messages for common issues
  - Retry logic for transient failures

## Testing

To test the integration:

1. Build the project:
```bash
go build .
```

2. Copy the example config:
```bash
cp github-copilot-example.json crush.json
```

3. Run Crush:
```bash
./crush run
```

4. Select GitHub Copilot as your provider when prompted

5. Send your first message - authentication will be triggered automatically

6. Follow the OAuth prompts in your terminal:
   - Open the displayed GitHub URL in your browser
   - Enter the device code shown in the terminal
   - Authorize Crush

7. Once authorized, the OAuth token will be saved and you can start chatting

**Note**: After the first successful authentication, you won't need to re-authenticate unless you revoke the token or delete it from your config.

## Available Models

Common models available through GitHub Copilot:
- `gpt-4o` - GPT-4 Optimized
- `gpt-4` - GPT-4
- `claude-opus-4` - Claude Opus 4
- `claude-sonnet-4` - Claude Sonnet 4
- `o1` - OpenAI o1 (reasoning model)
- `o1-mini` - OpenAI o1 Mini

Check GitHub Copilot documentation for the latest available models.

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Ensure you have an active GitHub Copilot Pro+ subscription
   - Check that you completed the OAuth flow within the time limit (usually 15 minutes)
   - Verify internet connectivity
   - Ensure you have browser access to complete authorization

2. **Token Expired or Invalid**
   - Copilot API tokens automatically refresh - if you see this error, the refresh may have failed
   - Try removing the `api_key` field from your `crush.json` to trigger re-authentication
   - Check if your OAuth token was revoked in GitHub settings

3. **"Authentication Required" on Every Run**
   - Verify that `crush.json` is being written to successfully
   - Check file permissions on `crush.json`
   - Ensure the `api_key` field is being saved after successful authentication

4. **Model Not Available**
   - Ensure the model ID in your config matches GitHub Copilot's available models
   - Check your subscription level (some models require Pro+)
   - Verify the model is still supported by GitHub Copilot

## Security Considerations

- **OAuth Token Storage**: GitHub OAuth tokens are persisted to `crush.json` as the `api_key` field. This allows authentication to persist across sessions without re-authorization.
- **Copilot API Tokens**: Short-lived (1 hour expiry) and stored in memory only. Automatically refreshed using the OAuth token.
- **Config File Security**: Ensure your `crush.json` file has appropriate permissions since it contains your OAuth token. Consider adding it to `.gitignore` if in a git repository.
- **Transport Security**: All API communication uses HTTPS
- **Token Revocation**: You can revoke access via your GitHub account settings at any time

## Future Enhancements

Potential improvements:
- Automatic model discovery from Copilot API
- Enhanced error messages for subscription issues  
- Support for GitHub Enterprise accounts
- Secure credential storage using system keychain
- Token refresh before expiry instead of on-demand
