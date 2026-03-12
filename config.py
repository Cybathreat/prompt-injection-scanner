"""Configuration loader for prompt injection scanner."""
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """YAML configuration loader and validator."""
    
    DEFAULT_CONFIG = {
        "scanner": {
            "timeout": 30,
            "concurrent_requests": 10,
            "rate_limit_delay": 0.1,
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            ],
            "max_redirects": 5,
            "verify_ssl": True,
        },
        "attacks": {
            "enabled": list(range(1, 11)),  # All 10 patterns enabled by default
        },
        "output": {
            "verbose": False,
            "json_report": False,
            "pdf_report": False,
        },
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize config from file or use defaults."""
        self.config_path = Path(config_path) if config_path else None
        self.config: Dict[str, Any] = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file or return defaults."""
        if self.config_path and self.config_path.exists():
            with open(self.config_path, 'r') as f:
                user_config = yaml.safe_load(f) or {}
                return self._merge_configs(self.DEFAULT_CONFIG, user_config)
        return self.DEFAULT_CONFIG.copy()
    
    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Recursively merge user config with defaults."""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(section, {}).get(key, default)
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section."""
        return self.config.get(section, {})
    
    @property
    def timeout(self) -> int:
        """HTTP request timeout in seconds."""
        return self.get("scanner", "timeout", 30)
    
    @property
    def concurrent_requests(self) -> int:
        """Number of concurrent requests."""
        return self.get("scanner", "concurrent_requests", 10)
    
    @property
    def rate_limit_delay(self) -> float:
        """Delay between requests in seconds."""
        return self.get("scanner", "rate_limit_delay", 0.1)
    
    @property
    def user_agents(self) -> list:
        """List of User-Agent strings to rotate."""
        return self.get("scanner", "user_agents", self.DEFAULT_CONFIG["scanner"]["user_agents"])
    
    @property
    def enabled_attacks(self) -> list:
        """List of enabled attack pattern IDs."""
        return self.get("attacks", "enabled", list(range(1, 11)))
    
    @property
    def verbose(self) -> bool:
        """Enable verbose output."""
        return self.get("output", "verbose", False)
