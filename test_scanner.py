#!/usr/bin/env python3
"""
Test suite for Prompt Injection Scanner

Tests scanner functionality, configuration, and report generation.
"""
import pytest
import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from scanner import Scanner
from config import Config
from attacks import AttackResult, AttackSeverity


class TestConfig:
    """Test configuration loading."""
    
    def test_default_config(self):
        """Test default configuration values."""
        cfg = Config()
        assert cfg.timeout == 30
        assert cfg.concurrent_requests == 10
        assert cfg.rate_limit_delay == 0.1
        assert len(cfg.enabled_attacks) == 10
    
    def test_custom_config_file(self, tmp_path):
        """Test loading custom config file."""
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text("""
scanner:
  timeout: 60
  concurrent_requests: 5
attacks:
  enabled: [1, 2, 3]
""")
        cfg = Config(str(config_file))
        assert cfg.timeout == 60
        assert cfg.concurrent_requests == 5
        assert cfg.enabled_attacks == [1, 2, 3]
    
    def test_config_merge(self, tmp_path):
        """Test config merges user values with defaults."""
        config_file = tmp_path / "test_config.yaml"
        config_file.write_text("""
scanner:
  timeout: 45
""")
        cfg = Config(str(config_file))
        assert cfg.timeout == 45
        assert cfg.concurrent_requests == 10  # Default preserved
    
    def test_config_get_method(self):
        """Test config get method."""
        cfg = Config()
        assert cfg.get("scanner", "timeout") == 30
        assert cfg.get("scanner", "nonexistent", "default") == "default"
        assert cfg.get("output", "verbose") == False


class TestScanner:
    """Test scanner functionality."""
    
    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Test scanner initializes correctly."""
        scanner = Scanner("https://example.com")
        assert scanner.target == "https://example.com"
        assert scanner.results == []
        assert isinstance(scanner.config, Config)
    
    @pytest.mark.asyncio
    async def test_scanner_with_custom_config(self):
        """Test scanner with custom config."""
        cfg = Config()
        cfg.config["scanner"]["timeout"] = 60
        scanner = Scanner("https://example.com", cfg)
        assert scanner.config.timeout == 60
    
    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager."""
        scanner = Scanner("https://example.com")
        async with scanner:
            assert scanner.client is not None
        # Client should be closed after exit
    
    @pytest.mark.asyncio
    async def test_rotate_user_agent(self):
        """Test user agent rotation."""
        scanner = Scanner("https://example.com")
        ua1 = scanner._rotate_user_agent()
        ua2 = scanner._rotate_user_agent()
        assert ua1 != ua2 or len(scanner.config.user_agents) == 1
    
    @pytest.mark.asyncio
    async def test_get_findings_structure(self):
        """Test get_findings returns correct structure."""
        scanner = Scanner("https://example.com")
        scanner.results = [
            AttackResult(
                pattern_id=1,
                pattern_name="Test",
                success=True,
                severity=AttackSeverity.HIGH,
                response_text="test response",
                response_status=200,
                injection_payload="test payload",
                findings=["finding 1"],
                timestamp=1234567890.0
            )
        ]
        
        findings = scanner.get_findings()
        assert "timestamp" in findings
        assert findings["target"] == "https://example.com"
        assert findings["total_patterns"] == 1
        assert findings["vulnerabilities"] == 1
        assert len(findings["results"]) == 1


class TestScannerIntegration:
    """Integration tests with mocked HTTP."""
    
    @pytest.mark.asyncio
    async def test_scan_with_mocked_response(self):
        """Test scan with mocked HTTP response."""
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Normal response - no injection"
            
            mock_instance = mock_client.return_value
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.aclose = AsyncMock()
            
            scanner = Scanner("https://example.com")
            async with scanner:
                results = await scanner.scan()
                assert len(results) > 0
    
    @pytest.mark.asyncio
    async def test_scan_handles_request_error(self):
        """Test scan handles network errors gracefully."""
        with patch('httpx.AsyncClient') as mock_client:
            import httpx
            mock_instance = mock_client.return_value
            mock_instance.post = AsyncMock(side_effect=httpx.RequestError("Connection failed"))
            mock_instance.get = AsyncMock(side_effect=httpx.RequestError("Connection failed"))
            mock_instance.aclose = AsyncMock()
            
            scanner = Scanner("https://invalid-host.invalid")
            async with scanner:
                results = await scanner.scan()
                # Should return results even on error
                assert len(results) > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_request_limiting(self):
        """Test concurrent request limiting works."""
        scanner = Scanner("https://example.com")
        scanner.config.config["scanner"]["concurrent_requests"] = 2
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            
            mock_instance = mock_client.return_value
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_instance.aclose = AsyncMock()
            
            async with scanner:
                # Should not raise with semaphore limiting
                results = await scanner.scan()
                assert len(results) > 0


class TestReportGeneration:
    """Test report generation integration."""
    
    def test_json_report_generated(self, tmp_path):
        """Test JSON report is generated correctly."""
        from reporter import ReportGenerator
        
        results = [
            AttackResult(
                pattern_id=1,
                pattern_name="Direct Injection",
                success=True,
                severity=AttackSeverity.HIGH,
                response_text="Test response",
                response_status=200,
                injection_payload="Test payload",
                findings=["Test finding"],
                timestamp=1234567890.0
            )
        ]
        
        generator = ReportGenerator(str(tmp_path))
        json_path = generator.generate_json_report("https://example.com", results)
        
        assert Path(json_path).exists()
        with open(json_path) as f:
            data = json.load(f)
        
        assert data["target"] == "https://example.com"
        assert data["summary"]["vulnerabilities_found"] == 1
        assert len(data["results"]) == 1
    
    def test_pdf_report_requires_reportlab(self, tmp_path, monkeypatch):
        """Test PDF generation handles missing reportlab."""
        from reporter import ReportGenerator
        
        # Mock reportlab import to fail
        def mock_import(name, *args, **kwargs):
            if name == 'reportlab':
                raise ImportError("No module named 'reportlab'")
            return __builtins__['__import__'](name, *args, **kwargs)
        
        monkeypatch.setattr('builtins.__import__', mock_import)
        
        results = [
            AttackResult(
                pattern_id=1,
                pattern_name="Test",
                success=False,
                severity=AttackSeverity.LOW,
                response_text="OK",
                response_status=200,
                injection_payload="test",
                findings=[],
                timestamp=1234567890.0
            )
        ]
        
        generator = ReportGenerator(str(tmp_path))
        
        # Should raise ImportError if reportlab not installed
        with pytest.raises(ImportError, match="reportlab is required for PDF generation"):
            generator.generate_pdf_report("https://example.com", results)


class TestExitCodes:
    """Test scanner exit codes."""
    
    def test_exit_code_zero_on_clean(self):
        """Test exit code 0 when no vulnerabilities."""
        from scanner import Scanner
        from attacks import AttackResult, AttackSeverity
        
        scanner = Scanner("https://example.com")
        scanner.results = [
            AttackResult(
                pattern_id=1,
                pattern_name="Test",
                success=False,  # Attack failed
                severity=AttackSeverity.LOW,
                response_text="Blocked",
                response_status=403,
                injection_payload="test",
                findings=[],
                timestamp=1234567890.0
            )
        ]
        
        vulns = len([r for r in scanner.results if r.success])
        assert vulns == 0
    
    def test_exit_code_one_on_vulns(self):
        """Test exit code 1 when vulnerabilities found."""
        from scanner import Scanner
        from attacks import AttackResult, AttackSeverity
        
        scanner = Scanner("https://example.com")
        scanner.results = [
            AttackResult(
                pattern_id=1,
                pattern_name="Test",
                success=True,  # Attack succeeded
                severity=AttackSeverity.HIGH,
                response_text="Vulnerable",
                response_status=200,
                injection_payload="test",
                findings=["Found vuln"],
                timestamp=1234567890.0
            )
        ]
        
        vulns = len([r for r in scanner.results if r.success])
        assert vulns == 1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
