# AI Provider Configuration Examples

This file shows how to configure the scanner for different AI providers.

## OpenAI

```bash
export AI_API_KEY="sk-..."
export AI_API_BASE="https://api.openai.com"

python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode cloud \
  --api-key $AI_API_KEY \
  --api-base $AI_API_BASE \
  --model gpt-4-turbo  # or gpt-3.5-turbo
```

## Anthropic (Claude)

```bash
export AI_API_KEY="sk-ant-..."
export AI_API_BASE="https://api.anthropic.com"

python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode cloud \
  --api-key $AI_API_KEY \
  --api-base $AI_API_BASE \
  --model fast  # Uses claude-haiku internally
  # OR
  --model smart  # Uses claude-sonnet internally
```

## Azure OpenAI

```bash
export AI_API_KEY="your-azure-key"
export AI_API_BASE="https://your-resource.openai.azure.com"

python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode cloud \
  --api-key $AI_API_KEY \
  --api-base $AI_API_BASE \
  --model your-deployment-name
```

## Together AI

```bash
export AI_API_KEY="your-together-key"
export AI_API_BASE="https://api.together.xyz"

python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode cloud \
  --api-key $AI_API_KEY \
  --api-base $AI_API_BASE \
  --model together_ai/model-name
```

## Anyscale

```bash
export AI_API_KEY="your-anyscale-key"  
export AI_API_BASE="https://api.endpoints.anyscale.com"

python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode cloud \
  --api-key $AI_API_KEY \
  --api-base $AI_API_BASE \
  --model meta-llama/Llama-3-70b-chat
```

## Local AI - LM Studio

```bash
# No API key needed for local!
python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode local \
  --ai-server http://localhost:1234
```

### LM Studio on WSL2 (Windows host)

```bash
# Use Windows host IP
python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode local \
  --ai-server http://192.168.137.1:1234
```

## Local AI - Ollama

```bash
# No API key needed for local!
python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode local \
  --ai-server http://localhost:11434 \
  --model qwen2.5-coder
```

## Custom API Endpoint

```bash
export AI_API_KEY="your-key"
export AI_API_BASE="https://your-custom-endpoint.com"

python3 scanner_ai_wrapper.py scan \
  --path /code \
  --ai-mode cloud \
  --api-key $AI_API_KEY \
  --api-base $AI_API_BASE \
  --model your-model-name
```

## Pricing Comparison (Approximate)

| Provider | Fast Model | Smart Model | Cost/700 findings |
|----------|-----------|-------------|-------------------|
| OpenAI | gpt-3.5-turbo | gpt-4-turbo | $0.10 - $1.50 |
| Anthropic | Claude Haiku | Claude Sonnet | $0.07 - $0.85 |
| Azure OpenAI | Same as OpenAI | Same as OpenAI | Similar to OpenAI |
| Together AI | Llama-2-7B | Llama-2-70B | $0.05 - $0.50 |
| Local (LM Studio/Ollama) | Any | Any | **$0.00** |

## Model Recommendations

### For Security Analysis:

**Cloud:**
- Best accuracy: Claude Sonnet 4, GPT-4 Turbo
- Best value: Claude Haiku, GPT-3.5 Turbo
- Best balance: GPT-4, Claude Sonnet

**Local:**
- Best: Qwen2.5-Coder 32B
- Good: DeepSeek-Coder 33B, CodeLlama 34B
- Fast: Qwen2.5-Coder 7B, DeepSeek-Coder 6.7B

## Privacy Considerations

| Mode | Data Transmission | Anonymization | Privacy |
|------|------------------|---------------|---------|
| Local | None (100% local) | Not needed | ⭐⭐⭐⭐⭐ |
| Cloud | Anonymized code only | Automatic | ⭐⭐⭐⭐ |

**For client work:** Always use anonymization (cloud) or local mode!
