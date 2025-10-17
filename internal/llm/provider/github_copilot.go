package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/llm/tools"
	"github.com/charmbracelet/crush/internal/log"
	"github.com/charmbracelet/crush/internal/message"
	"github.com/google/uuid"
	"github.com/openai/openai-go"
	"github.com/openai/openai-go/option"
	"github.com/openai/openai-go/packages/param"
	"github.com/openai/openai-go/shared"
)

const (
	githubCopilotBaseURL   = "https://api.githubcopilot.com"
	githubCopilotModelsURL = "https://api.githubcopilot.com/models"
)

type githubCopilotClient struct {
	providerOptions providerClientOptions
	client          openai.Client
	auth            *GitHubCopilotAuth
	cachedModels    []catwalk.Model
}

type GitHubCopilotModelResponse struct {
	Data []struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		ContextWindow   int    `json:"context_window,omitempty"`
		MaxOutputTokens int    `json:"max_output_tokens,omitempty"`
		Capabilities    struct {
			Type     string `json:"type,omitempty"`
			Function struct {
				SupportsToolChoice bool `json:"supports_tool_choice,omitempty"`
			} `json:"function,omitempty"`
		} `json:"capabilities,omitempty"`
	} `json:"data"`
}

type GitHubCopilotClient ProviderClient

func newGitHubCopilotClient(opts providerClientOptions) GitHubCopilotClient {
	auth := NewGitHubCopilotAuth(nil)

	if opts.apiKey != "" {
		auth.SetGitHubOAuthToken(opts.apiKey)
	}

	auth.SetTokenSaveCallback(func(token string) error {
		return config.Get().SetProviderAPIKey(opts.config.ID, token)
	})

	client := &githubCopilotClient{
		providerOptions: opts,
		client:          createGitHubCopilotOpenAIClient(opts, auth),
		auth:            auth,
	}

	// Fetch available models from the API and update the config if not already cached
	go client.fetchAndUpdateModels()

	return client
}

// fetchAndUpdateModels fetches models from GitHub Copilot API and updates the provider config
func (g *githubCopilotClient) fetchAndUpdateModels() {
	// Skip if we already have cached models
	if len(g.cachedModels) > 0 {
		return
	}

	// Skip if no API key is available yet
	if g.providerOptions.apiKey == "" {
		slog.Debug("Skipping GitHub Copilot model fetch - no API key available")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fetchedModels, err := g.FetchAvailableModels(ctx)
	if err != nil {
		slog.Warn("Failed to fetch GitHub Copilot models from API", "error", err)
		return
	}

	if len(fetchedModels) == 0 {
		slog.Debug("No models fetched from GitHub Copilot API")
		return
	}

	// Update the provider config with fetched models
	cfg := config.Get()
	providerConfig, exists := cfg.Providers.Get(g.providerOptions.config.ID)
	if !exists {
		return
	}

	// Merge fetched models with existing configured models
	seen := make(map[string]bool)
	var mergedModels []catwalk.Model

	// User-configured models take precedence
	for _, model := range providerConfig.Models {
		if !seen[model.ID] {
			seen[model.ID] = true
			if model.Name == "" {
				model.Name = model.ID
			}
			mergedModels = append(mergedModels, model)
		}
	}

	// Add fetched models that aren't already configured
	for _, model := range fetchedModels {
		if !seen[model.ID] {
			seen[model.ID] = true
			if model.Name == "" {
				model.Name = model.ID
			}
			mergedModels = append(mergedModels, model)
		}
	}

	providerConfig.Models = mergedModels
	cfg.Providers.Set(g.providerOptions.config.ID, providerConfig)

	slog.Info("Fetched and updated GitHub Copilot models", "count", len(fetchedModels), "total", len(mergedModels))
}

func createGitHubCopilotOpenAIClient(opts providerClientOptions, auth *GitHubCopilotAuth) openai.Client {
	baseURL := githubCopilotBaseURL
	if opts.baseURL != "" {
		resolvedBaseURL, err := config.Get().Resolve(opts.baseURL)
		if err == nil && resolvedBaseURL != "" {
			baseURL = resolvedBaseURL
		}
	}

	openaiClientOptions := []option.RequestOption{
		option.WithBaseURL(baseURL),
		option.WithMiddleware(createGitHubCopilotMiddleware(auth)),
	}

	if config.Get().Options.Debug {
		httpClient := log.NewHTTPClient()
		openaiClientOptions = append(openaiClientOptions, option.WithHTTPClient(httpClient))
	}

	for key, value := range opts.extraHeaders {
		openaiClientOptions = append(openaiClientOptions, option.WithHeader(key, value))
	}

	for extraKey, extraValue := range opts.extraBody {
		openaiClientOptions = append(openaiClientOptions, option.WithJSONSet(extraKey, extraValue))
	}

	return openai.NewClient(openaiClientOptions...)
}

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
		req.Header.Set("Openai-Intent", "conversation-edits")

		if isAgentRequest(req) {
			req.Header.Set("X-Initiator", "agent")
		} else {
			req.Header.Set("X-Initiator", "user")
		}

		if isVisionRequest(req) {
			req.Header.Set("Copilot-Vision-Request", "true")
		}

		return next(req)
	}
}

func isAgentRequest(req *http.Request) bool {
	if req.Body == nil {
		return false
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return false
	}
	req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	var payload struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return false
	}

	for _, msg := range payload.Messages {
		if msg.Role == "tool" || msg.Role == "assistant" {
			return true
		}
	}

	return false
}

func isVisionRequest(req *http.Request) bool {
	if req.Body == nil {
		return false
	}

	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		return false
	}
	req.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	var payload struct {
		Messages []struct {
			Content interface{} `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return false
	}

	for _, msg := range payload.Messages {
		if contentArray, ok := msg.Content.([]interface{}); ok {
			for _, part := range contentArray {
				if partMap, ok := part.(map[string]interface{}); ok {
					if partType, ok := partMap["type"].(string); ok && partType == "image_url" {
						return true
					}
				}
			}
		}
	}

	return false
}

func (g *githubCopilotClient) convertMessages(messages []message.Message) (openaiMessages []openai.ChatCompletionMessageParamUnion) {
	systemMessage := g.providerOptions.systemMessage
	if g.providerOptions.systemPromptPrefix != "" {
		systemMessage = g.providerOptions.systemPromptPrefix + "\n" + systemMessage
	}

	system := openai.SystemMessage(systemMessage)
	openaiMessages = append(openaiMessages, system)

	for _, msg := range messages {
		switch msg.Role {
		case message.User:
			var content []openai.ChatCompletionContentPartUnionParam

			textBlock := openai.ChatCompletionContentPartTextParam{Text: msg.Content().String()}
			content = append(content, openai.ChatCompletionContentPartUnionParam{OfText: &textBlock})

			hasBinaryContent := false
			for _, binaryContent := range msg.BinaryContent() {
				hasBinaryContent = true
				imageURL := openai.ChatCompletionContentPartImageImageURLParam{URL: binaryContent.String(catwalk.InferenceProviderOpenAI)}
				imageBlock := openai.ChatCompletionContentPartImageParam{ImageURL: imageURL}

				content = append(content, openai.ChatCompletionContentPartUnionParam{OfImageURL: &imageBlock})
			}

			if hasBinaryContent {
				openaiMessages = append(openaiMessages, openai.UserMessage(content))
			} else {
				openaiMessages = append(openaiMessages, openai.UserMessage(msg.Content().String()))
			}

		case message.Assistant:
			assistantMsg := openai.ChatCompletionAssistantMessageParam{
				Role: "assistant",
			}

			if len(msg.ToolCalls()) > 0 {
				finished := make([]message.ToolCall, 0, len(msg.ToolCalls()))
				for _, call := range msg.ToolCalls() {
					if call.Finished {
						finished = append(finished, call)
					}
				}
				if len(finished) > 0 {
					assistantMsg.ToolCalls = make([]openai.ChatCompletionMessageToolCallParam, len(finished))
					for i, call := range finished {
						assistantMsg.ToolCalls[i] = openai.ChatCompletionMessageToolCallParam{
							ID:   call.ID,
							Type: "function",
							Function: openai.ChatCompletionMessageToolCallFunctionParam{
								Name:      call.Name,
								Arguments: call.Input,
							},
						}
					}
				}
			}
			if msg.Content().String() != "" {
				assistantMsg.Content = openai.ChatCompletionAssistantMessageParamContentUnion{
					OfString: param.NewOpt(msg.Content().Text),
				}
			}

			if msg.Content().String() == "" && len(assistantMsg.ToolCalls) == 0 {
				continue
			}

			openaiMessages = append(openaiMessages, openai.ChatCompletionMessageParamUnion{
				OfAssistant: &assistantMsg,
			})

		case message.Tool:
			for _, result := range msg.ToolResults() {
				openaiMessages = append(openaiMessages,
					openai.ToolMessage(result.Content, result.ToolCallID),
				)
			}
		}
	}

	return openaiMessages
}

func (g *githubCopilotClient) convertTools(tools []tools.BaseTool) []openai.ChatCompletionToolParam {
	openaiTools := make([]openai.ChatCompletionToolParam, len(tools))

	for i, tool := range tools {
		info := tool.Info()
		openaiTools[i] = openai.ChatCompletionToolParam{
			Function: openai.FunctionDefinitionParam{
				Name:        info.Name,
				Description: openai.String(info.Description),
				Parameters: openai.FunctionParameters{
					"type":       "object",
					"properties": info.Parameters,
					"required":   info.Required,
				},
			},
		}
	}

	return openaiTools
}

func (g *githubCopilotClient) finishReason(reason string) message.FinishReason {
	switch reason {
	case "stop":
		return message.FinishReasonEndTurn
	case "length":
		return message.FinishReasonMaxTokens
	case "tool_calls":
		return message.FinishReasonToolUse
	default:
		return message.FinishReasonUnknown
	}
}

func (g *githubCopilotClient) preparedParams(messages []openai.ChatCompletionMessageParamUnion, tools []openai.ChatCompletionToolParam) openai.ChatCompletionNewParams {
	model := g.providerOptions.model(g.providerOptions.modelType)
	cfg := config.Get()

	modelConfig := cfg.Models[config.SelectedModelTypeLarge]
	if g.providerOptions.modelType == config.SelectedModelTypeSmall {
		modelConfig = cfg.Models[config.SelectedModelTypeSmall]
	}

	reasoningEffort := modelConfig.ReasoningEffort

	params := openai.ChatCompletionNewParams{
		Model:    openai.ChatModel(model.ID),
		Messages: messages,
		Tools:    tools,
	}

	maxTokens := model.DefaultMaxTokens
	if modelConfig.MaxTokens > 0 {
		maxTokens = modelConfig.MaxTokens
	}

	if g.providerOptions.maxTokens > 0 {
		maxTokens = g.providerOptions.maxTokens
	}

	if model.CanReason {
		params.MaxCompletionTokens = openai.Int(maxTokens)
		switch reasoningEffort {
		case "low":
			params.ReasoningEffort = shared.ReasoningEffortLow
		case "medium":
			params.ReasoningEffort = shared.ReasoningEffortMedium
		case "high":
			params.ReasoningEffort = shared.ReasoningEffortHigh
		case "minimal":
			params.ReasoningEffort = shared.ReasoningEffort("minimal")
		default:
			params.ReasoningEffort = shared.ReasoningEffort(reasoningEffort)
		}
	} else {
		params.MaxTokens = openai.Int(maxTokens)
	}

	return params
}

func (g *githubCopilotClient) send(ctx context.Context, messages []message.Message, tools []tools.BaseTool) (response *ProviderResponse, err error) {
	params := g.preparedParams(g.convertMessages(messages), g.convertTools(tools))
	attempts := 0
	for {
		attempts++
		openaiResponse, err := g.client.Chat.Completions.New(ctx, params)

		if err != nil {
			retry, after, retryErr := g.shouldRetry(attempts, err)
			if retryErr != nil {
				return nil, retryErr
			}
			if retry {
				slog.Warn("Retrying due to error", "attempt", attempts, "max_retries", maxRetries, "error", err)
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(after) * time.Millisecond):
					continue
				}
			}
			return nil, retryErr
		}

		if len(openaiResponse.Choices) == 0 {
			return nil, fmt.Errorf("received empty response from GitHub Copilot API")
		}

		content := ""
		if openaiResponse.Choices[0].Message.Content != "" {
			content = openaiResponse.Choices[0].Message.Content
		}

		toolCalls := g.toolCalls(*openaiResponse)
		finishReason := g.finishReason(string(openaiResponse.Choices[0].FinishReason))

		if len(toolCalls) > 0 {
			finishReason = message.FinishReasonToolUse
		}

		return &ProviderResponse{
			Content:      content,
			ToolCalls:    toolCalls,
			Usage:        g.usage(*openaiResponse),
			FinishReason: finishReason,
		}, nil
	}
}

func (g *githubCopilotClient) stream(ctx context.Context, messages []message.Message, tools []tools.BaseTool) <-chan ProviderEvent {
	params := g.preparedParams(g.convertMessages(messages), g.convertTools(tools))
	params.StreamOptions = openai.ChatCompletionStreamOptionsParam{
		IncludeUsage: openai.Bool(true),
	}

	attempts := 0
	eventChan := make(chan ProviderEvent)

	go func() {
		for {
			attempts++
			if len(params.Tools) == 0 {
				params.Tools = nil
			}
			openaiStream := g.client.Chat.Completions.NewStreaming(ctx, params)

			acc := openai.ChatCompletionAccumulator{}
			currentContent := ""
			toolCalls := make([]message.ToolCall, 0)
			msgToolCalls := make(map[int64]openai.ChatCompletionMessageToolCall)
			toolMap := make(map[string]openai.ChatCompletionMessageToolCall)
			toolCallIDMap := make(map[string]string)

			for openaiStream.Next() {
				chunk := openaiStream.Current()
				if len(chunk.Choices) != 0 && len(chunk.Choices[0].Delta.ToolCalls) > 0 && chunk.Choices[0].Delta.ToolCalls[0].Index == -1 {
					chunk.Choices[0].Delta.ToolCalls[0].Index = 0
				}
				acc.AddChunk(chunk)

				for i, choice := range chunk.Choices {
					reasoning, ok := choice.Delta.JSON.ExtraFields["reasoning"]
					if ok && reasoning.Raw() != "" {
						reasoningStr := ""
						json.Unmarshal([]byte(reasoning.Raw()), &reasoningStr)
						if reasoningStr != "" {
							eventChan <- ProviderEvent{
								Type:     EventThinkingDelta,
								Thinking: reasoningStr,
							}
						}
					}
					if choice.Delta.Content != "" {
						eventChan <- ProviderEvent{
							Type:    EventContentDelta,
							Content: choice.Delta.Content,
						}
						currentContent += choice.Delta.Content
					} else if len(choice.Delta.ToolCalls) > 0 {
						toolCall := choice.Delta.ToolCalls[0]
						if strings.HasPrefix(toolCall.ID, "functions.") {
							exID, ok := toolCallIDMap[toolCall.ID]
							if !ok {
								newID := uuid.NewString()
								toolCallIDMap[toolCall.ID] = newID
								toolCall.ID = newID
							} else {
								toolCall.ID = exID
							}
						}
						newToolCall := false
						if existingToolCall, ok := msgToolCalls[toolCall.Index]; ok {
							if toolCall.ID != "" && toolCall.ID != existingToolCall.ID {
								found := false
								for _, tool := range msgToolCalls {
									if tool.ID == toolCall.ID {
										existingToolCall.Function.Arguments += toolCall.Function.Arguments
										msgToolCalls[toolCall.Index] = existingToolCall
										toolMap[existingToolCall.ID] = existingToolCall
										found = true
									}
								}
								if !found {
									newToolCall = true
								}
							} else {
								existingToolCall.Function.Arguments += toolCall.Function.Arguments
								msgToolCalls[toolCall.Index] = existingToolCall
								toolMap[existingToolCall.ID] = existingToolCall
							}
						} else {
							newToolCall = true
						}
						if newToolCall {
							if toolCall.ID == "" {
								toolCall.ID = uuid.NewString()
							}
							eventChan <- ProviderEvent{
								Type: EventToolUseStart,
								ToolCall: &message.ToolCall{
									ID:       toolCall.ID,
									Name:     toolCall.Function.Name,
									Finished: false,
								},
							}
							msgToolCalls[toolCall.Index] = openai.ChatCompletionMessageToolCall{
								ID:   toolCall.ID,
								Type: "function",
								Function: openai.ChatCompletionMessageToolCallFunction{
									Name:      toolCall.Function.Name,
									Arguments: toolCall.Function.Arguments,
								},
							}
							toolMap[toolCall.ID] = msgToolCalls[toolCall.Index]
						}
						toolCalls := []openai.ChatCompletionMessageToolCall{}
						for _, tc := range toolMap {
							toolCalls = append(toolCalls, tc)
						}
						acc.Choices[i].Message.ToolCalls = toolCalls
					}
				}
			}

			err := openaiStream.Err()
			if err == nil || errors.Is(err, io.EOF) {
				if len(acc.Choices) == 0 {
					eventChan <- ProviderEvent{
						Type:  EventError,
						Error: fmt.Errorf("received empty streaming response from GitHub Copilot API"),
					}
					return
				}

				resultFinishReason := acc.Choices[0].FinishReason
				if resultFinishReason == "" {
					resultFinishReason = "stop"
				}

				finishReason := g.finishReason(resultFinishReason)
				if len(acc.Choices[0].Message.ToolCalls) > 0 {
					toolCalls = append(toolCalls, g.toolCalls(acc.ChatCompletion)...)
				}
				if len(toolCalls) > 0 {
					finishReason = message.FinishReasonToolUse
				}

				eventChan <- ProviderEvent{
					Type: EventComplete,
					Response: &ProviderResponse{
						Content:      currentContent,
						ToolCalls:    toolCalls,
						Usage:        g.usage(acc.ChatCompletion),
						FinishReason: finishReason,
					},
				}
				close(eventChan)
				return
			}

			retry, after, retryErr := g.shouldRetry(attempts, err)
			if retryErr != nil {
				eventChan <- ProviderEvent{Type: EventError, Error: retryErr}
				close(eventChan)
				return
			}
			if retry {
				slog.Warn("Retrying due to error", "attempt", attempts, "max_retries", maxRetries, "error", err)
				select {
				case <-ctx.Done():
					if ctx.Err() != nil {
						eventChan <- ProviderEvent{Type: EventError, Error: ctx.Err()}
					}
					close(eventChan)
					return
				case <-time.After(time.Duration(after) * time.Millisecond):
					continue
				}
			}
			eventChan <- ProviderEvent{Type: EventError, Error: retryErr}
			close(eventChan)
			return
		}
	}()

	return eventChan
}

func (g *githubCopilotClient) shouldRetry(attempts int, err error) (bool, int64, error) {
	if attempts > maxRetries {
		return false, 0, fmt.Errorf("maximum retry attempts reached: %d retries", maxRetries)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false, 0, err
	}

	var apiErr *openai.Error
	retryMs := 0
	retryAfterValues := []string{}

	if errors.As(err, &apiErr) {
		if apiErr.StatusCode == http.StatusUnauthorized {
			ctx := context.Background()
			if err := g.auth.ExchangeForCopilotToken(ctx); err != nil {
				return false, 0, fmt.Errorf("failed to refresh copilot token: %w", err)
			}
			g.client = createGitHubCopilotOpenAIClient(g.providerOptions, g.auth)
			return true, 0, nil
		}

		if apiErr.StatusCode == http.StatusTooManyRequests {
			if apiErr.Type == "insufficient_quota" || apiErr.Code == "insufficient_quota" {
				return false, 0, fmt.Errorf("GitHub Copilot quota exceeded: %s", apiErr.Message)
			}
		} else if apiErr.StatusCode != http.StatusInternalServerError {
			return false, 0, err
		}

		if apiErr.Response != nil {
			retryAfterValues = apiErr.Response.Header.Values("Retry-After")
		}
	}

	if apiErr != nil {
		slog.Warn("GitHub Copilot API error", "status_code", apiErr.StatusCode, "message", apiErr.Message, "type", apiErr.Type)
		if len(retryAfterValues) > 0 {
			slog.Warn("Retry-After header", "values", retryAfterValues)
		}
	} else {
		slog.Error("GitHub Copilot API error", "error", err.Error(), "attempt", attempts, "max_retries", maxRetries)
	}

	backoffMs := 2000 * (1 << (attempts - 1))
	jitterMs := int(float64(backoffMs) * 0.2)
	retryMs = backoffMs + jitterMs
	if len(retryAfterValues) > 0 {
		if _, err := fmt.Sscanf(retryAfterValues[0], "%d", &retryMs); err == nil {
			retryMs = retryMs * 1000
		}
	}
	return true, int64(retryMs), nil
}

func (g *githubCopilotClient) toolCalls(completion openai.ChatCompletion) []message.ToolCall {
	var toolCalls []message.ToolCall

	if len(completion.Choices) > 0 && len(completion.Choices[0].Message.ToolCalls) > 0 {
		for _, call := range completion.Choices[0].Message.ToolCalls {
			if call.Function.Name == "" {
				continue
			}
			toolCall := message.ToolCall{
				ID:       call.ID,
				Name:     call.Function.Name,
				Input:    call.Function.Arguments,
				Type:     "function",
				Finished: true,
			}
			toolCalls = append(toolCalls, toolCall)
		}
	}

	return toolCalls
}

func (g *githubCopilotClient) usage(completion openai.ChatCompletion) TokenUsage {
	cachedTokens := completion.Usage.PromptTokensDetails.CachedTokens
	inputTokens := completion.Usage.PromptTokens - cachedTokens

	return TokenUsage{
		InputTokens:         inputTokens,
		OutputTokens:        completion.Usage.CompletionTokens,
		CacheCreationTokens: 0,
		CacheReadTokens:     cachedTokens,
	}
}

func (g *githubCopilotClient) FetchAvailableModels(ctx context.Context) ([]catwalk.Model, error) {
	if len(g.cachedModels) > 0 {
		return g.cachedModels, nil
	}

	token, err := g.auth.GetValidToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get valid token: %w", err)
	}

	models, err := fetchGitHubCopilotModels(ctx, token)
	if err != nil {
		return nil, err
	}

	g.cachedModels = models
	return models, nil
}

// FetchGitHubCopilotModels fetches available models from the GitHub Copilot API using a provided OAuth token.
// This is a standalone function that can be called without creating a full client instance.
func FetchGitHubCopilotModels(ctx context.Context, oauthToken string) ([]catwalk.Model, error) {
	return fetchGitHubCopilotModels(ctx, oauthToken)
}

func fetchGitHubCopilotModels(ctx context.Context, token string) ([]catwalk.Model, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", githubCopilotModelsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", githubCopilotUserAgent)
	req.Header.Set("Editor-Version", githubCopilotEditorVersion)
	req.Header.Set("Editor-Plugin-Version", githubCopilotPluginVersion)
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github copilot models API returned status %d: %s", resp.StatusCode, string(body))
	}

	var modelsResp GitHubCopilotModelResponse
	if err := json.NewDecoder(resp.Body).Decode(&modelsResp); err != nil {
		return nil, fmt.Errorf("failed to decode models response: %w", err)
	}

	models := make([]catwalk.Model, 0, len(modelsResp.Data))
	for _, apiModel := range modelsResp.Data {
		model := catwalk.Model{
			ID:   apiModel.ID,
			Name: apiModel.Name,
		}

		if apiModel.ContextWindow > 0 {
			model.ContextWindow = int64(apiModel.ContextWindow)
		} else {
			model.ContextWindow = 128000
		}

		if apiModel.MaxOutputTokens > 0 {
			model.DefaultMaxTokens = int64(apiModel.MaxOutputTokens)
		} else {
			model.DefaultMaxTokens = 4096
		}

		if strings.Contains(strings.ToLower(apiModel.ID), "o1") || strings.Contains(strings.ToLower(apiModel.Name), "thinking") {
			model.CanReason = true
		}

		models = append(models, model)
	}

	return models, nil
}

func (g *githubCopilotClient) Model() catwalk.Model {
	return g.providerOptions.model(g.providerOptions.modelType)
}
