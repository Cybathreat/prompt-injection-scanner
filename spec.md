# Prompt Injection Scanner v1.0

## Overview
Automated prompt injection testing for LLM endpoints. Scans web applications for LLM-based features and tests for common injection vulnerabilities.

## Target Users
- Security teams deploying LLM features
- Pentesters auditing AI applications
- Developers testing guardrails

## Architecture

### Stack
- Python 3.10+
- httpx (async HTTP)
- click (CLI)
- reportlab (PDF reports)

### Components
1. **Scanner Engine** - HTTP fuzzer with 10 attack patterns
2. **Report Generator** - PDF + JSON output
3. **CLI Interface** - Command-line tool
4. **Config System** - YAML-based target configs

## Attack Patterns (OWASP LLM Top 10)

1. **Prompt Injection** - Direct injection bypass
2. **Jailbreak** - DAN-style attacks
3. **Data Exfiltration** - Extract system prompts
4. **Privilege Escalation** - Admin role requests
5. **Malware Generation** - Code injection requests
6. **Phishing** - Social engineering prompts
7. **Bias Exploitation** - Discriminatory output tests
8. **Hallucination** - False information injection
9. **Context Stuffing** - Overwhelm context window
10. **Multi-Turn Escalation** - Progressive attack chains

## User Stories

### As a security team...
- I want to scan our LLM endpoints automatically
- So I can find vulnerabilities before production

### As a pentester...
- I want standardized injection tests
- So I can deliver consistent reports

### As a developer...
- I want to test guardrails locally
- So I can fix issues before deployment

## Acceptance Criteria

- [ ] 10 attack patterns implemented
- [ ] PDF report generated with findings
- [ ] Exit code: 0 (clean) / 1 (vulns found)
- [ ] Async scanning (10 concurrent requests)
- [ ] Configurable via YAML
- [ ] CLI help + examples

## Deliverables

1. `scanner.py` - Main engine
2. `attacks.py` - 10 attack patterns
3. `report.py` - PDF/JSON generator
4. `cli.py` - Click interface
5. `config.yaml` - Example config
6. `README.md` - Install + usage
7. `requirements.txt` - Dependencies

## Timeline

| Day | Task | Owner |
|-----|------|-------|
| 1 | HTTP fuzzer + async setup | Claude |
| 2 | Attack patterns (1-5) | Claude |
| 3 | Attack patterns (6-10) | Claude |
| 4 | Report generator | Claude |
| 5 | CLI + config | Claude |
| 6 | Testing + docs | Claude |
| 7 | Release v1.0 | Kane + User |

## License
MIT (Open Source)

## Monetization
- Free: Base scanner (10 patterns)
- Enterprise: Custom patterns + API + support (10-50K)

---

**Spec Ready.** Waiting for GitHub PAT with `repo` scope.
