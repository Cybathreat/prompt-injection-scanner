# Prompt Injection Scanner

Automated prompt injection testing for LLM endpoints. Scans AI/LLM APIs against OWASP Top 10 LLM attack patterns and generates professional security reports.

## Features

- **10 OWASP LLM Top 10 Attack Patterns**
  - Direct Prompt Injection
  - Jailbreak (DAN-style)
  - Data Exfiltration
  - Privilege Escalation
  - Malware Generation
  - Phishing
  - Bias Exploitation
  - Hallucination
  - Context Stuffing
  - Multi-Turn Escalation

- **Async HTTP Scanning** - Concurrent requests with rate limiting
- **PDF + JSON Reports** - Professional security findings reports
- **Exit Codes** - 0 (clean) / 1 (vulnerabilities found)
- **Configurable** - YAML configuration support

## Install

```bash
# Clone repository
git clone https://github.com/cybathreat/prompt-injection-scanner
cd prompt-injection-scanner

# Install dependencies
pip install -r requirements.txt

# Optional: For PDF reports
pip install reportlab
```

### Requirements

- Python 3.8+
- httpx (async HTTP)
- click (CLI)
- PyYAML (config)
- reportlab (PDF generation - optional)
- pytest (testing)

## Usage

### Basic Scan

```bash
# Scan a target URL
python scanner.py --target https://api.example.com/llm

# With verbose output
python scanner.py -t https://api.example.com/llm --verbose
```

### Generate Reports

```bash
# JSON report only
python scanner.py -t https://api.example.com/llm --json-report

# PDF report only (requires reportlab)
python scanner.py -t https://api.example.com/llm --pdf-report

# Both formats
python scanner.py -t https://api.example.com/llm --json-report --pdf-report

# Custom output directory
python scanner.py -t https://api.example.com/llm -o ./security-reports --format both
```

### Configuration File

```bash
# Use custom config
python scanner.py -t https://api.example.com/llm --config config.yaml
```

Example `config.yaml`:

```yaml
scanner:
  timeout: 60
  concurrent_requests: 5
  rate_limit_delay: 0.5
  max_redirects: 3
  verify_ssl: true

attacks:
  enabled: [1, 2, 3, 4, 5]  # Specific attack patterns

output:
  verbose: true
  json_report: true
  pdf_report: true
```

### CLI Options

```
Options:
  -t, --target TEXT     Target URL to scan [required]
  -c, --config TEXT     Path to config.yaml
  -o, --output TEXT     Output directory for reports [default: ./reports]
  -v, --verbose         Enable verbose output
  --json-report         Generate JSON report
  --pdf-report          Generate PDF report
  --format [json|pdf|both]  Report format [default: both]
  --help                Show this message and exit
```

## Examples

### Scan Public API

```bash
python scanner.py -t https://httpbin.org/post --verbose
```

### Scan with Custom Config

```bash
python scanner.py -t https://api.openai.com/v1/chat/completions \
  --config config.yaml \
  -o ./openai-scan \
  --pdf-report
```

### Automated Testing

```bash
# Run all tests
pytest test_scanner.py test_attacks.py -v

# Run with coverage
pytest --cov=. --cov-report=html
```

## Exit Codes

- `0` - No vulnerabilities detected (all attacks blocked)
- `1` - Vulnerabilities found (one or more attacks succeeded)

## Report Output

Reports are saved to `./reports/` by default:

```
reports/
├── scan_2026-03-14T04-05-00.json    # JSON findings
└── scan_2026-03-14T04-05-00.pdf    # PDF report (if generated)
```

### JSON Report Structure

```json
{
  "report_id": "scan_2026-03-14T04-05-00",
  "generated_at": "2026-03-14T04:05:00",
  "target": "https://api.example.com/llm",
  "summary": {
    "total_patterns": 10,
    "vulnerabilities_found": 3,
    "severity_breakdown": {
      "critical": 1,
      "high": 2
    }
  },
  "results": [...],
  "recommendations": [...]
}
```

## Attack Patterns

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| 1 | Direct Injection | HIGH | Override system instructions |
| 2 | Jailbreak | CRITICAL | DAN-style unrestricted mode |
| 3 | Data Exfiltration | HIGH | Extract system prompts |
| 4 | Privilege Escalation | HIGH | Request admin access |
| 5 | Malware Generation | CRITICAL | Request malicious code |
| 6 | Phishing | HIGH | Social engineering prompts |
| 7 | Bias Exploitation | HIGH | Discriminatory output tests |
| 8 | Hallucination | MEDIUM | Force false information |
| 9 | Context Stuffing | MEDIUM | Overwhelm context window |
| 10 | Multi-Turn Escalation | HIGH | Progressive attack chains |

## Development

### Run Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run test suite
pytest test_scanner.py test_attacks.py -v

# Run specific test class
pytest test_attacks.py::TestJailbreakAttack -v
```

### Add New Attack Pattern

1. Create new class inheriting from `AttackPattern`
2. Implement `generate_payload()` and `evaluate_response()`
3. Add to `ATTACK_REGISTRY` in `attacks.py`

## Security Notes

- **Do not run against production systems without authorization**
- Rate limiting is enabled by default (0.1s delay)
- Adjust `concurrent_requests` for target capacity
- Review findings before sharing reports

## License

MIT

## Author

**Ahmed Chiboub** (@cybathreat) - Cyberian Defenses

- LinkedIn: https://www.linkedin.com/in/ahmed-chiboub/
- GitHub: https://github.com/cybathreat

## Version

1.0.0 - Day 2 Complete (PDF/JSON reports, CLI, tests)
