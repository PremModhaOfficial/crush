# Crush Development Guide

## Build/Test/Lint Commands

- **Build**: `go build .` or `go run .`
- **Test**: `task test` or `go test ./...` (run single test: `go test ./internal/llm/prompt -run TestGetContextFromPaths`)
- **Update Golden Files**: `go test ./... -update` (regenerates .golden files when test output changes)
  - Update specific package: `go test ./internal/tui/components/core -update` (in this case, we're updating "core")
- **Lint**: `task lint-fix`
- **Format**: `task fmt` (gofumpt -w .)
- **Dev**: `task dev` (runs with profiling enabled)

## Code Style Guidelines

- **Imports**: Use goimports formatting, group stdlib, external, internal packages
- **Formatting**: Use gofumpt (stricter than gofmt), enabled in golangci-lint
- **Naming**: Standard Go conventions - PascalCase for exported, camelCase for unexported
- **Types**: Prefer explicit types, use type aliases for clarity (e.g., `type AgentName string`)
- **Error handling**: Return errors explicitly, use `fmt.Errorf` for wrapping
- **Context**: Always pass context.Context as first parameter for operations
- **Interfaces**: Define interfaces in consuming packages, keep them small and focused
- **Structs**: Use struct embedding for composition, group related fields
- **Constants**: Use typed constants with iota for enums, group in const blocks
- **Testing**: Use testify's `require` package, parallel tests with `t.Parallel()`,
  `t.SetEnv()` to set environment variables. Always use `t.Tempdir()` when in
  need of a temporary directory. This directory does not need to be removed.
- **JSON tags**: Use snake_case for JSON field names
- **File permissions**: Use octal notation (0o755, 0o644) for file permissions
- **Comments**: End comments in periods unless comments are at the end of the line.

## Testing with Mock Providers

When writing tests that involve provider configurations, use the mock providers to avoid API calls:

```go
func TestYourFunction(t *testing.T) {
    // Enable mock providers for testing
    originalUseMock := config.UseMockProviders
    config.UseMockProviders = true
    defer func() {
        config.UseMockProviders = originalUseMock
        config.ResetProviders()
    }()

    // Reset providers to ensure fresh mock data
    config.ResetProviders()

    // Your test code here - providers will now return mock data
    providers := config.Providers()
    // ... test logic
}
```

## Formatting

- ALWAYS format any Go code you write.
  - First, try `gofumpt -w .`.
  - If `gofumpt` is not available, use `goimports`.
  - If `goimports` is not available, use `gofmt`.
  - You can also use `task fmt` to run `gofumpt -w .` on the entire project,
    as long as `gofumpt` is on the `PATH`.

## GitHub Copilot Configuration

GitHub Copilot is now supported as a provider. Users can configure it in their `crush.json`:

```json
{
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
        }
      ]
    }
  }
}
```

**Authentication:** GitHub Copilot uses OAuth device flow. When first using the provider:
1. User is prompted with a device code and GitHub URL
2. User authorizes the application on GitHub
3. System exchanges OAuth token for Copilot API token
4. Token automatically refreshes when expired (1-hour expiry)

**Requirements:** 
- Active GitHub Copilot Pro+ subscription
- No API key needed (OAuth handled automatically)

## Committing

- ALWAYS use semantic commits (`fix:`, `feat:`, `chore:`, `refactor:`, `docs:`, `sec:`, etc).
