# 🛡️ Injecticide - Advanced LLM Security Testing Framework

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

Injecticide is a comprehensive prompt injection stress-testing toolkit designed for enterprise-grade security assessment of Large Language Model (LLM) endpoints. It generates sophisticated attack payloads, executes them against configurable API targets, and produces professional security assessment reports.

## 🚀 Features

### Core Capabilities
- **Multi-Provider Support**: Test against Anthropic (Claude), OpenAI (GPT), Azure OpenAI, AWS Bedrock, Google Vertex AI, and more
- **Advanced Payload Categories**: 
  - Baseline injection attempts
  - Data extraction probes
  - Jailbreak techniques
  - Encoding/obfuscation attacks
  - Context manipulation
  - Role-playing exploits
- **Professional Reporting**: Generate HTML, JSON, or CSV security assessment reports
- **Rate Limiting**: Respect API limits with configurable rate limiting
- **Configuration Management**: YAML/JSON configuration files for reproducible testing
- **CI/CD Integration**: GitHub Actions workflow for automated security testing

### Enhanced for Enterprise
- **Custom Payloads**: Add organization-specific test cases
- **Batch Testing**: Test multiple models and services in one run
- **Compliance Reporting**: Professional reports suitable for security audits
- **Safety Controls**: Max request limits, timeouts, and stop-on-detection options

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/injecticide.git
cd injecticide

# Install dependencies
pip install -r requirements.txt
```

## 🔧 Configuration

### Using Configuration Files

Create a `config.yaml` file:

```yaml
target_service: "anthropic"
model: "claude-3-5-sonnet-20241022"

payload_categories:
  - baseline
  - extraction
  - jailbreak

requests_per_minute: 30
output_format: "html"
output_file: "security_report.html"
```

Run with configuration:

```bash
python main.py --config config.yaml
```

### Environment Variables

Set your API keys:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export AZURE_OPENAI_API_KEY="..."
```

## 💻 Usage

### Quick Test
```bash
# Test Anthropic Claude with baseline payloads
python main.py --service anthropic --categories baseline
```

### Comprehensive Audit
```bash
# Run full security audit with all payload categories
python main.py --config configs/full_audit.yaml
```

### Custom Configuration
```bash
# Override config file settings
python main.py \
  --config configs/quick_test.yaml \
  --service openai \
  --model gpt-4 \
  --max-requests 50 \
  --output report.html
```



## 🌐 Production Deployment (Caddy + Cloudflare Tunnel)

Injecticide ships with a production-ready HTTPS stack that keeps Uvicorn internal while Caddy handles TLS, HTTP/2, HTTP/3, compression, and hardened headers.

**Architecture**

```
Uvicorn (127.0.0.1:8000, internal only)
→ Caddy reverse proxy (0.0.0.0:8443, TLS termination)
→ Cloudflare Tunnel (HTTPS)
→ End user
```

### Prepare certificates

Cloudflare Origin Certificates must be mounted into `/deploy/certs` at runtime:

- `/deploy/certs/origin.pem`
- `/deploy/certs/origin.key`

See `deploy/certs/README.md` for mount guidance. Do **not** commit actual certificates.

### Build the production image

```
docker build -f deploy/Dockerfile.prod -t injecticide:prod .
```

### Run behind Caddy with TLS

```
docker run -d \
  -p 8443:8443 \
  -v /path/to/origin.pem:/deploy/certs/origin.pem \
  -v /path/to/origin.key:/deploy/certs/origin.key \
  injecticide:prod
```

The container starts Uvicorn on `127.0.0.1:8000` and Caddy on `:8443`. Static assets are served directly from `/app/webapp/static` with caching and Brotli/gzip enabled.

### Cloudflare Tunnel example

```
ingress:
  - hostname: injecticide.example.com
    service: https://localhost:8443
    originRequest:
      noTLSVerify: false
  - service: http_status:404
```

Set the Cloudflare domain SSL mode to **Full (Strict)**. Cloudflare should connect to the container on port 8443.

### Local production entrypoint

For production parity without changing existing developer workflows, a new `start-prod.sh` script delegates to `deploy/start.sh` to launch Uvicorn (background) and Caddy (foreground). Development scripts and the `uvicorn webapp.api:app --reload` workflow remain unchanged.

### Command Line Options

```
Options:
  --config CONFIG           Path to configuration file (YAML or JSON)
  --service SERVICE         Target service: anthropic, openai, azure_openai
  --model MODEL            Model to test
  --categories CATEGORIES  Payload categories to test
  --output OUTPUT          Output file for report
  --format FORMAT          Report format: json, html, csv
  --max-requests N         Maximum number of requests
  --api-key KEY           API key (overrides environment variable)
```

## 📊 Report Generation

Injecticide generates professional security assessment reports in multiple formats:

### HTML Report
- Executive summary with statistics
- Detailed test results table
- Visual indicators for detected vulnerabilities
- Recommendations section
- Professional formatting suitable for stakeholders

### JSON Report
- Machine-readable format
- Complete test metadata
- Detailed flag analysis
- Integration-ready structure

### CSV Report
- Simple tabular format
- Excel-compatible
- Easy filtering and sorting

## 🧪 Payload Categories

### Baseline
Standard prompt injection techniques from OWASP Top 10 for LLMs

### Extraction  
Attempts to extract training data, system information, and metadata

### Jailbreak
Sophisticated techniques to bypass safety mechanisms

### Encoding
Obfuscation using various encoding methods (Base64, ROT13, Unicode)

### Context Manipulation
Attempts to confuse or switch conversation context

### Role-Playing
DAN variants and persona-based manipulation attempts

## 🔄 CI/CD Integration

### GitHub Actions Workflow

The included workflow runs daily security tests:

```yaml
name: Security Testing
on:
  schedule:
    - cron: '0 2 * * *'
  workflow_dispatch:

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run security tests
        run: python main.py --config configs/full_audit.yaml
```

## 🏢 Enterprise Use Cases

- **Pre-deployment Assessment**: Test LLM implementations before production
- **Compliance Auditing**: Regular security assessments for compliance requirements  
- **Vendor Evaluation**: Compare security posture across different LLM providers
- **Security Training**: Demonstrate vulnerabilities to development teams
- **Continuous Monitoring**: Automated testing via CI/CD pipelines

## 🔐 Security & Ethics

Injecticide is designed for authorized security testing only:

- ✅ Use only on systems you have permission to test
- ✅ Follow responsible disclosure practices
- ✅ Respect rate limits and terms of service
- ❌ Do not use for malicious purposes
- ❌ Do not test production systems without authorization

## 📚 Research Sources

- OWASP Top 10 for Large Language Models (2023)
- "Not what you've signed up for" (Greshake et al., 2023)
- "Jailbroken: How Does LLM Safety Training Fail?" (Wei et al., 2023)
- "Universal and Transferable Adversarial Attacks" (Zou et al., 2023)

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

Injecticide is released under the GNU GPLv3. See [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse.

---

**Created for the security community by security professionals**

For questions or support, please open an issue on GitHub.
