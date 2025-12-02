# Security Scanner - AI Integration

**Version:** 2.6.0  
**False Positive Reduction:** Up to 71.4%  
**Cost:** As low as $0.07 per 700 findings (cloud) or $0.00 (local)

## Overview

This security scanner integrates AI assistance to dramatically reduce false positives in automated security scanning. It supports three modes:

1. **Cloud AI** - Use any OpenAI-compatible cloud API for maximum accuracy
2. **Local AI** - Run 100% locally with LM Studio, Ollama, or similar tools (FREE, private)
3. **Traditional** - Standard scanning without AI assistance

### Key Features

✅ **Multiple AI Backends** - Cloud API, Local AI, or no AI  
✅ **Code Anonymization** - Client data never leaves your control when using cloud  
✅ **Cost Tracking** - Monitor API costs in real-time  
✅ **High Accuracy** - 71.4% false positive reduction in testing  
✅ **Flexible** - Works with any OpenAI-compatible API  
✅ **Privacy-First** - Anonymization ensures NDA compliance

## Quick Start

### 1. Traditional Mode (No AI)

```bash
python3 scanner_ai_wrapper.py scan --path /code/to/scan --ai-mode none
```

### 2. Local AI Mode (FREE, 100% Private)

```bash
# Start LM Studio or Ollama
# Load a model (recommended: Qwen2.5-Coder, DeepSeek-Coder)

python3 scanner_ai_wrapper.py scan \
  --path /code/to/scan \
  --ai-mode local \
  --ai-server http://localhost:1234
```

### 3. Cloud AI Mode (Maximum Accuracy)

```bash
export AI_API_KEY="your-api-key-here"

python3 scanner_ai_wrapper.py scan \
  --path /code/to/scan \
  --ai-mode cloud \
  --api-key $AI_API_KEY \
  --model fast  # or 'smart' for better accuracy
```

## Installation

```bash
# Clone repository
git clone https://github.com/netcuter/security-scanner-ai
cd security-scanner-ai

# Install dependencies
pip install requests

# Optional: For cloud AI with Anthropic API
pip install anthropic
```

## Usage Examples

### Basic Scan

```bash
python3 scanner_ai_wrapper.py scan --path /tmp/webapp
```

### Scan with Local AI

```bash
python3 scanner_ai_wrapper.py scan \
  --path /tmp/webapp \
  --ai-mode local \
  --ai-server http://192.168.1.100:1234
```

### Scan with Cloud AI (Custom Endpoint)

```bash
python3 scanner_ai_wrapper.py scan \
  --path /tmp/webapp \
  --ai-mode cloud \
  --api-key sk-xxxxx \
  --api-base https://api.openai.com \
  --model gpt-4
```

### Save Results to File

```bash
python3 scanner_ai_wrapper.py scan \
  --path /tmp/webapp \
  --ai-mode cloud \
  --output results.txt
```

### JSON Output

```bash
python3 scanner_ai_wrapper.py scan \
  --path /tmp/webapp \
  --ai-mode local \
  --json > results.json
```

## Architecture

```
┌─────────────────────────────────────────────┐
│         Security Scanner Core               │
│  (Traditional vulnerability detection)      │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
         ┌─────────────────┐
         │  AI Filter      │  ← YOU ARE HERE
         │  (Optional)     │
         └────┬───────┬────┘
              │       │
     ┌────────┘       └────────┐
     ▼                         ▼
┌─────────────┐         ┌─────────────┐
│  Cloud AI   │         │  Local AI   │
│  (Accurate) │         │  (Private)  │
└─────────────┘         └─────────────┘
     │                         │
     ▼                         ▼
┌─────────────────────────────────┐
│      Anonymization Layer        │
│  (Cloud mode only - protects   │
│   client data, ensures NDA      │
│   compliance)                   │
└─────────────────────────────────┘
```

## Code Anonymization

When using cloud AI, all code is anonymized before transmission:

**Original Code:**
```python
# Client: XYZ Corp
conn = psycopg2.connect("host=prod-db.xyzcorp.com password=secret123")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Anonymized Code (sent to cloud):**
```python

conn = psycopg2.connect("string_a3f29b4c")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**What's Preserved:**
- SQL keywords (SELECT, INSERT, etc.)
- Dangerous functions (eval, exec, cursor.execute)
- Vulnerability patterns
- Code structure

**What's Anonymized:**
- Client names and comments
- File paths
- Connection strings
- Non-security string literals

## Performance

Based on real-world testing with 700 findings:

| Mode | FP Reduction | Time | Cost | Privacy |
|------|-------------|------|------|---------|
| None | 0% | 1 min | $0 | ✅ 100% |
| Local AI | ~50% | 60 min | $0 | ✅ 100% |
| Cloud (fast) | ~71% | 10 min | $0.07 | ✅ Anonymized |
| Cloud (smart) | ~85% | 15 min | $0.85 | ✅ Anonymized |

## Configuration

### Cloud AI Configuration

```bash
# Environment variables
export AI_API_KEY="your-key"
export AI_API_BASE="https://api.openai.com"  # or any OpenAI-compatible API

# Command line
python3 scanner_ai_wrapper.py scan \
  --api-key $AI_API_KEY \
  --api-base $AI_API_BASE \
  --model gpt-4  # or any supported model
```

### Local AI Configuration

**LM Studio:**
```bash
# 1. Install LM Studio
# 2. Load model (e.g., Qwen2.5-Coder-7B)
# 3. Enable local server (port 1234)

python3 scanner_ai_wrapper.py scan \
  --ai-mode local \
  --ai-server http://localhost:1234
```

**Ollama:**
```bash
# 1. Install Ollama
# 2. Pull model: ollama pull qwen2.5-coder
# 3. Run server

python3 scanner_ai_wrapper.py scan \
  --ai-mode local \
  --ai-server http://localhost:11434
```

## API Compatibility

This scanner works with any API that implements OpenAI-compatible endpoints:

- ✅ OpenAI API
- ✅ Anthropic API (with adapter)
- ✅ Azure OpenAI
- ✅ Together AI
- ✅ Anyscale
- ✅ Replicate
- ✅ LM Studio (local)
- ✅ Ollama (local)
- ✅ vLLM (local)
- ✅ Any other OpenAI-compatible server

## Pricing

### Cloud AI (varies by provider)

**Fast Tier:**
- Input: ~$0.25/1M tokens
- Output: ~$1.25/1M tokens
- Typical cost: $0.07 per 700 findings

**Smart Tier:**
- Input: ~$3.00/1M tokens
- Output: ~$15.00/1M tokens
- Typical cost: $0.85 per 700 findings

### Local AI

**100% FREE** - Runs on your hardware

Recommended models:
- Qwen2.5-Coder (7B, 14B, 32B)
- DeepSeek-Coder (6.7B, 33B)
- CodeLlama (7B, 13B, 34B)

## Security & Privacy

### Data Protection

1. **Local AI Mode**: Zero data transmission - everything stays on your machine
2. **Cloud AI Mode**: Code anonymized before transmission
3. **NDA Compliance**: Anonymization ensures no client-identifiable information leaves your control

### What Gets Anonymized

- ❌ Client names and references
- ❌ File paths and directory structures  
- ❌ Connection strings and credentials
- ❌ Comments and documentation
- ❌ Business logic details

### What Stays Intact

- ✅ Vulnerability patterns
- ✅ Security keywords (SQL, eval, exec, etc.)
- ✅ Code structure
- ✅ Exploitability context

## Troubleshooting

### Local AI Connection Issues

```bash
# Test connection
curl http://localhost:1234/v1/models

# If using WSL2 with Windows LM Studio
python3 scanner_ai_wrapper.py scan \
  --ai-server http://192.168.137.1:1234  # Windows host IP
```

### Cloud API Issues

```bash
# Test API key
export AI_API_KEY="your-key"
python3 -c "from ai_cloud_api import CloudAIAssistant; \
             a = CloudAIAssistant(api_key='$AI_API_KEY'); \
             print('✅ API key valid')"
```

### Import Errors

```bash
# Install missing dependencies
pip install requests anthropic
```

## Development

### Project Structure

```
.
├── scanner_ai_wrapper.py    # Main CLI wrapper
├── ai_cloud_api.py          # Cloud AI integration
├── ai_local.py              # Local AI integration
├── code_anonymizer.py       # Anonymization engine
└── README.md                # This file
```

### Adding New AI Providers

1. Extend `CloudAIAssistant` class
2. Implement provider-specific authentication
3. Map to OpenAI-compatible endpoints
4. Update model tier mappings

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

## License

MIT License - see LICENSE file

## Support

For issues and questions:
- GitHub Issues: https://github.com/netcuter/security-scanner-ai/issues
- Documentation: https://github.com/netcuter/security-scanner-ai/wiki

## Changelog

### v2.6.0 (Current)
- ✨ Added cloud AI support
- ✨ Added local AI support (LM Studio, Ollama)
- ✨ Implemented code anonymization
- ✨ Added cost tracking
- ✨ Multiple AI provider support

### v2.5.1
- 🔧 Improved scanner accuracy
- 🔧 Better error handling

---

**Made with ❤️ for the security community**
