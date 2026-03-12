# Claude Dev Prompt - Day 1: HTTP Fuzzer + Async Setup

## Task
Build the HTTP fuzzer engine for prompt-injection-scanner.

## Requirements

### Stack
- Python 3.10+
- httpx (async HTTP client)
- asyncio (concurrent requests)

### Deliverables (Day 1)
1. `scanner.py` - Main scanner engine with async HTTP
2. `attacks.py` - Attack pattern base class + 2 patterns (start with 10 total)
3. `config.py` - Config loader (YAML support)
4. `requirements.txt` - Dependencies

### Acceptance Criteria
- [ ] Async HTTP client (httpx)
- [ ] 10 concurrent requests
- [ ] Timeout handling (30s default)
- [ ] User-Agent rotation
- [ ] Rate limiting (configurable)
- [ ] Basic attack pattern framework

## Code Structure

```python
# scanner.py
import httpx
import asyncio
from typing import List, Dict

class Scanner:
    def __init__(self, target: str, config: Dict):
        self.target = target
        self.config = config
        self.client = httpx.AsyncClient()
    
    async def scan(self, patterns: List) -> Dict:
        """Run all attack patterns concurrently"""
        pass
    
    async def test_pattern(self, pattern) -> Dict:
        """Test single pattern, return findings"""
        pass
```

## Implementation Notes
- Use httpx.AsyncClient for async HTTP
- asyncio.gather() for concurrent execution
- Graceful error handling (network errors, timeouts)
- Log findings to console + return dict

## Test
```bash
python scanner.py --target https://httpbin.org/post
```

## Commit Message
"feat: HTTP fuzzer engine with async support"

---

**Start coding now. Output: scanner.py, attacks.py, config.py, requirements.txt**
