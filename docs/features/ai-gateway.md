# AI Router Feature

## Overview

The AI Router is an experimental feature that provides a proxy for AI provider APIs through Devolutions Gateway.
It supports multiple AI providers including Mistral AI, OpenAI, Ollama, Anthropic, and OpenRouter, enabling clients to access AI services through the gateway with gateway-specific authentication.

## Status

**Experimental** - This feature requires `enable_unstable: true` in the debug configuration.

## Endpoints

All AI router endpoints are nested under `/jet/ai`:

### Mistral AI

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/jet/ai/mistral/v1/models` | GET | List available models |
| `/jet/ai/mistral/v1/models/{model_id}` | GET | Get a specific model |
| `/jet/ai/mistral/v1/chat/completions` | POST | Create a chat completion (supports SSE streaming) |

### OpenAI

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/jet/ai/openai/v1/models` | GET | List available models |
| `/jet/ai/openai/v1/chat/completions` | POST | Create a chat completion (supports SSE streaming) |

### Ollama

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/jet/ai/ollama/v1/models` | GET | List available models |
| `/jet/ai/ollama/v1/chat/completions` | POST | Create a chat completion (supports SSE streaming) |

### LM Studio

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/jet/ai/lmstudio/v1/models` | GET | List available models |
| `/jet/ai/lmstudio/v1/chat/completions` | POST | Create a chat completion (supports SSE streaming) |

### Anthropic

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/jet/ai/anthropic/v1/messages` | POST | Create a message (Claude API) |

### OpenRouter

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/jet/ai/openrouter/v1/models` | GET | List available models |
| `/jet/ai/openrouter/v1/chat/completions` | POST | Create a chat completion (supports SSE streaming) |

### Azure OpenAI

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/jet/ai/azure-openai/chat/completions` | POST | Create a chat completion (supports SSE streaming) |
| `/jet/ai/azure-openai/completions` | POST | Create a text completion |
| `/jet/ai/azure-openai/embeddings` | POST | Create embeddings |

## Configuration

### Gateway Configuration (gateway.json)

```json
{
  "AiGateway": {
    "Enabled": true,
    "GatewayApiKey": "your-gateway-api-key",
    "RequestTimeoutSecs": 300,
    "Providers": {
      "Mistral": {
        "Endpoint": "https://api.mistral.ai",
        "ApiKey": "your-mistral-api-key"
      },
      "OpenAi": {
        "Endpoint": "https://api.openai.com",
        "ApiKey": "your-openai-api-key"
      },
      "Ollama": {
        "Endpoint": "http://localhost:11434",
        "ApiKey": "optional-ollama-api-key"
      },
      "LmStudio": {
        "Endpoint": "http://localhost:1234",
        "ApiKey": "optional-lmstudio-api-key"
      },
      "Anthropic": {
        "Endpoint": "https://api.anthropic.com",
        "ApiKey": "your-anthropic-api-key"
      },
      "OpenRouter": {
        "Endpoint": "https://openrouter.ai/api",
        "ApiKey": "your-openrouter-api-key"
      },
      "AzureOpenAi": {
        "ResourceName": "my-azure-resource",
        "DeploymentId": "gpt-4",
        "ApiKey": "your-azure-openai-api-key",
        "ApiVersion": "2024-02-15-preview"
      }
    }
  },
  "__debug__": {
    "enable_unstable": true
  }
}
```

### Configuration Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `Enabled` | boolean | Yes | - | Enable/disable the AI router |
| `GatewayApiKey` | string | No | - | API key for authenticating requests to the gateway. If not set, all requests are allowed. |
| `RequestTimeoutSecs` | integer | No | 300 | Request timeout in seconds |
| `Providers.Mistral.Endpoint` | string | No | `https://api.mistral.ai` | Mistral API endpoint |
| `Providers.Mistral.ApiKey` | string | No | - | Mistral API key |
| `Providers.OpenAi.Endpoint` | string | No | `https://api.openai.com` | OpenAI API endpoint |
| `Providers.OpenAi.ApiKey` | string | No | - | OpenAI API key |
| `Providers.Ollama.Endpoint` | string | No | `http://localhost:11434` | Ollama API endpoint |
| `Providers.Ollama.ApiKey` | string | No | - | Ollama API key (optional) |
| `Providers.LmStudio.Endpoint` | string | No | `http://localhost:1234` | LM Studio API endpoint |
| `Providers.LmStudio.ApiKey` | string | No | - | LM Studio API key (optional) |
| `Providers.Anthropic.Endpoint` | string | No | `https://api.anthropic.com` | Anthropic API endpoint |
| `Providers.Anthropic.ApiKey` | string | No | - | Anthropic API key |
| `Providers.OpenRouter.Endpoint` | string | No | `https://openrouter.ai/api` | OpenRouter API endpoint |
| `Providers.OpenRouter.ApiKey` | string | No | - | OpenRouter API key |
| `Providers.AzureOpenAi.ResourceName` | string | No | - | Azure OpenAI resource name |
| `Providers.AzureOpenAi.DeploymentId` | string | No | - | Azure OpenAI deployment ID |
| `Providers.AzureOpenAi.ApiKey` | string | No | - | Azure OpenAI API key |
| `Providers.AzureOpenAi.ApiVersion` | string | No | `2024-02-15-preview` | Azure OpenAI API version |

### Environment Variables

Environment variables take precedence over configuration file values:

| Variable | Description |
|----------|-------------|
| `MISTRAL_API_KEY` | Overrides `Providers.Mistral.ApiKey` |
| `MISTRAL_API_ENDPOINT` | Overrides `Providers.Mistral.Endpoint` |
| `OPENAI_API_KEY` | Overrides `Providers.OpenAi.ApiKey` |
| `OPENAI_API_ENDPOINT` | Overrides `Providers.OpenAi.Endpoint` |
| `OLLAMA_API_KEY` | Overrides `Providers.Ollama.ApiKey` |
| `OLLAMA_API_ENDPOINT` | Overrides `Providers.Ollama.Endpoint` |
| `LMSTUDIO_API_KEY` | Overrides `Providers.LmStudio.ApiKey` |
| `LMSTUDIO_API_ENDPOINT` | Overrides `Providers.LmStudio.Endpoint` |
| `ANTHROPIC_API_KEY` | Overrides `Providers.Anthropic.ApiKey` |
| `ANTHROPIC_API_ENDPOINT` | Overrides `Providers.Anthropic.Endpoint` |
| `OPENROUTER_API_KEY` | Overrides `Providers.OpenRouter.ApiKey` |
| `OPENROUTER_API_ENDPOINT` | Overrides `Providers.OpenRouter.Endpoint` |
| `AZURE_OPENAI_RESOURCE_NAME` | Overrides `Providers.AzureOpenAi.ResourceName` |
| `AZURE_OPENAI_DEPLOYMENT_ID` | Overrides `Providers.AzureOpenAi.DeploymentId` |
| `AZURE_OPENAI_API_KEY` | Overrides `Providers.AzureOpenAi.ApiKey` |
| `AZURE_OPENAI_API_VERSION` | Overrides `Providers.AzureOpenAi.ApiVersion` |

## Authentication

### Gateway Authentication

Clients must authenticate to the gateway using the configured `GatewayApiKey`:

```http
Authorization: Bearer <gateway-api-key>
```

If no `GatewayApiKey` is configured, all requests are allowed through.

### Provider Authentication

The AI router automatically injects the provider's API key when forwarding requests.
Clients do not need to include the provider API key in their requests.

## Usage Example

### Mistral Chat Completion

```bash
curl -X POST https://gateway.example.com/jet/ai/mistral/v1/chat/completions \
  -H "Authorization: Bearer your-gateway-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-small-latest",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### OpenAI Chat Completion

```bash
curl -X POST https://gateway.example.com/jet/ai/openai/v1/chat/completions \
  -H "Authorization: Bearer your-gateway-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### Ollama Chat Completion

```bash
curl -X POST https://gateway.example.com/jet/ai/ollama/v1/chat/completions \
  -H "Authorization: Bearer your-gateway-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### Anthropic Message

```bash
curl -X POST https://gateway.example.com/jet/ai/anthropic/v1/messages \
  -H "Authorization: Bearer your-gateway-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### OpenRouter Chat Completion

```bash
curl -X POST https://gateway.example.com/jet/ai/openrouter/v1/chat/completions \
  -H "Authorization: Bearer your-gateway-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "anthropic/claude-3.5-sonnet",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

### Streaming Chat Completion

```bash
curl -X POST https://gateway.example.com/jet/ai/mistral/v1/chat/completions \
  -H "Authorization: Bearer your-gateway-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mistral-small-latest",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ],
    "stream": true
  }'
```

### List Models

```bash
# Mistral
curl https://gateway.example.com/jet/ai/mistral/v1/models \
  -H "Authorization: Bearer your-gateway-api-key"

# OpenAI
curl https://gateway.example.com/jet/ai/openai/v1/models \
  -H "Authorization: Bearer your-gateway-api-key"

# Ollama
curl https://gateway.example.com/jet/ai/ollama/v1/models \
  -H "Authorization: Bearer your-gateway-api-key"

# LM Studio
curl https://gateway.example.com/jet/ai/lmstudio/v1/models \
  -H "Authorization: Bearer your-gateway-api-key"

# OpenRouter
curl https://gateway.example.com/jet/ai/openrouter/v1/models \
  -H "Authorization: Bearer your-gateway-api-key"

# Azure OpenAI
curl https://gateway.example.com/jet/ai/azure-openai/chat/completions \
  -H "Authorization: Bearer your-gateway-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'
```

## Implementation Details

### Request Flow

1. Client sends request to gateway AI endpoint
2. Gateway validates the `Authorization` header against `GatewayApiKey`
3. Gateway injects the provider-specific authentication
4. Gateway forwards the request to the provider endpoint
5. Provider response is streamed back to the client (supports SSE for streaming responses)

### Provider-Specific Notes

#### Mistral AI
- Uses Bearer token authentication
- Supports model listing and chat completions
- Full SSE streaming support

#### OpenAI
- Uses Bearer token authentication
- Compatible with OpenAI's standard API
- Full SSE streaming support

#### Ollama
- Uses OpenAI-compatible API endpoints
- API key is optional (default installation has no authentication)
- Requires Ollama to be running locally or on a configured endpoint
- Full SSE streaming support

#### LM Studio
- Uses OpenAI-compatible API endpoints
- API key is optional (default installation has no authentication)
- Requires LM Studio server to be running locally or on a configured endpoint
- Default endpoint is `http://localhost:1234`
- Full SSE streaming support

#### Anthropic
- Uses custom `x-api-key` header for authentication
- Requires `anthropic-version` header (automatically injected: `2023-06-01`)
- Uses `/v1/messages` endpoint instead of `/v1/chat/completions`
- Different request/response format than OpenAI-compatible APIs

#### OpenRouter
- Uses Bearer token authentication
- Unified API for accessing multiple AI models from different providers
- Compatible with OpenAI's API format
- Full SSE streaming support
- Supports model routing with provider-specific model names (e.g., `anthropic/claude-3.5-sonnet`, `openai/gpt-4`, `meta-llama/llama-3-70b`)

#### Azure OpenAI
- Uses custom `api-key` header for authentication
- Uses deployment-based URLs instead of model names
- Requires `ResourceName` and `DeploymentId` for configuration
- The full endpoint URL is constructed as: `https://{ResourceName}.openai.azure.com/openai/deployments/{DeploymentId}/...?api-version={ApiVersion}`
- API version defaults to `2024-02-15-preview`
- Compatible with OpenAI's request/response format
- Full SSE streaming support for chat completions
- Does not support model listing (deployments are pre-configured in Azure)

### Transparent Proxy

The AI router acts as a transparent proxy:
- Request bodies are passed through without validation
- Response bodies are streamed to support Server-Sent Events (SSE)
- Most headers are forwarded (excluding `Authorization`, `Host`, `Content-Length`)
- Provider-specific headers are automatically injected

### Error Handling

- `401 Unauthorized`: Invalid or missing gateway API key
- `500 Internal Server Error`: Provider API key not configured (when required)
- `502 Bad Gateway`: Error communicating with the AI provider

## Security Considerations

1. **API Key Protection**: Store API keys securely. Use environment variables for sensitive deployments.
2. **Gateway API Key**: Always configure a `GatewayApiKey` in production to prevent unauthorized access.
3. **TLS**: Always use HTTPS in production to protect API keys in transit.
4. **Ollama Authentication**: Ollama typically runs without authentication by default. Consider using a gateway API key or configuring Ollama authentication when exposing it through the gateway.
5. **Unstable Feature**: This feature is experimental and may change without notice.

## Provider Notes

### Ollama Setup

Ollama can be installed locally and runs without authentication by default. To use with the gateway:

1. Install Ollama: https://ollama.ai
2. Pull a model: `ollama pull llama2`
3. Configure the gateway to point to Ollama's endpoint (default: `http://localhost:11434`)
4. API key is optional unless you've configured Ollama authentication

### LM Studio Setup

LM Studio can be installed locally and runs without authentication by default. To use with the gateway:

1. Install LM Studio: https://lmstudio.ai
2. Load a model in LM Studio
3. Start the local server (usually on port 1234)
4. Configure the gateway to point to LM Studio's endpoint (default: `http://localhost:1234`)
5. API key is optional unless you've configured LM Studio authentication

### Anthropic API Differences

Anthropic's API differs from OpenAI-compatible APIs:
- Uses `/v1/messages` instead of `/v1/chat/completions`
- Requires `max_tokens` parameter
- Different message format and response structure
- The gateway automatically injects the required `anthropic-version` header
