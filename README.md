# Prompt Injection Scanner

Automated prompt injection testing for LLM endpoints.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
python scanner.py --target https://api.example.com/llm
python scanner.py --config config.yaml
```

## Features

- 10 OWASP LLM Top 10 attack patterns
- Async HTTP scanning
- PDF + JSON reports
- Exit codes: 0 (clean) / 1 (vulns found)

## License

MIT

## Author

Ahmed Chiboub (@cybathreat) - Cyberian Defenses
