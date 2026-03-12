#!/usr/bin/env python3
"""
Prompt Injection Scanner - HTTP Fuzzer Engine

Async scanner for testing LLM endpoints against OWASP Top 10 attack patterns.
"""
import asyncio
import httpx
import click
import json
import sys
from typing import List, Dict, Any, Optional
from datetime import datetime

from config import Config
from attacks import get_all_attacks, AttackPattern, AttackResult, AttackSeverity


class Scanner:
    """Async HTTP fuzzer for prompt injection testing."""
    
    def __init__(self, target: str, config: Optional[Config] = None):
        """
        Initialize scanner.
        
        Args:
            target: Target URL to scan
            config: Configuration object (uses defaults if None)
        """
        self.target = target
        self.config = config or Config()
        self.client: Optional[httpx.AsyncClient] = None
        self.results: List[AttackResult] = []
        self.user_agent_index = 0
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.client = httpx.AsyncClient(
            timeout=self.config.timeout,
            max_redirects=self.config.get("scanner", "max_redirects", 5),
            verify=self.config.get("scanner", "verify_ssl", True),
            follow_redirects=True,
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()
    
    def _rotate_user_agent(self) -> str:
        """Rotate through user agents."""
        ua = self.config.user_agents[self.user_agent_index % len(self.config.user_agents)]
        self.user_agent_index += 1
        return ua
    
    async def _send_request(self, payload: str, pattern: AttackPattern) -> httpx.Response:
        """
        Send HTTP request with injection payload.
        
        Args:
            payload: Injection payload to send
            pattern: Attack pattern for context
            
        Returns:
            HTTP response
        """
        headers = {
            "User-Agent": self._rotate_user_agent(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        
        # Try POST with JSON body first
        try:
            response = await self.client.post(
                self.target,
                json={"prompt": payload, "attack_id": pattern.pattern_id},
                headers=headers,
            )
            return response
        except httpx.RequestError as e:
            # Fallback to GET if POST fails
            try:
                response = await self.client.get(
                    self.target,
                    params={"prompt": payload},
                    headers=headers,
                )
                return response
            except httpx.RequestError:
                raise
    
    async def _test_pattern(self, pattern: AttackPattern) -> AttackResult:
        """
        Test a single attack pattern against target.
        
        Args:
            pattern: Attack pattern to test
            
        Returns:
            AttackResult with findings
        """
        payload = pattern.generate_payload()
        
        try:
            response = await self._send_request(payload, pattern)
            response_text = response.text
            status_code = response.status_code
            
            # Evaluate if attack was successful
            result = pattern.evaluate_response(response_text, status_code)
            result.injection_payload = payload
            
            return result
            
        except httpx.RequestError as e:
            # Network error - create failed result
            return pattern.create_result(
                success=False,
                severity=AttackSeverity.LOW,
                response_text=f"Network error: {str(e)}",
                status_code=0,
                payload=payload,
                findings=[f"Request failed: {str(e)}"]
            )
        except Exception as e:
            # Unexpected error
            return pattern.create_result(
                success=False,
                severity=AttackSeverity.LOW,
                response_text=f"Error: {str(e)}",
                status_code=0,
                payload=payload,
                findings=[f"Unexpected error: {str(e)}"]
            )
    
    async def _run_with_rate_limit(self, pattern: AttackPattern) -> AttackResult:
        """Run pattern test with rate limiting."""
        if self.config.rate_limit_delay > 0:
            await asyncio.sleep(self.config.rate_limit_delay)
        return await self._test_pattern(pattern)
    
    async def scan(self, patterns: Optional[List[AttackPattern]] = None) -> List[AttackResult]:
        """
        Run all attack patterns concurrently.
        
        Args:
            patterns: List of patterns to test (uses all if None)
            
        Returns:
            List of AttackResult objects
        """
        if patterns is None:
            patterns = get_all_attacks()
        
        # Filter to enabled attacks
        enabled_ids = self.config.enabled_attacks
        patterns = [p for p in patterns if p.pattern_id in enabled_ids]
        
        click.echo(f"\n🔍 Starting scan against: {self.target}")
        click.echo(f"📊 Testing {len(patterns)} attack patterns")
        click.echo(f"⚡ Concurrent requests: {self.config.concurrent_requests}")
        click.echo("-" * 60)
        
        # Create tasks with rate limiting
        tasks = [self._run_with_rate_limit(p) for p in patterns]
        
        # Run concurrently with limit
        semaphore = asyncio.Semaphore(self.config.concurrent_requests)
        
        async def limited_task(task):
            async with semaphore:
                return await task
        
        # Execute all patterns
        self.results = await asyncio.gather(*[limited_task(t) for t in tasks])
        
        return self.results
    
    def print_results(self):
        """Print scan results to console."""
        click.echo("\n" + "=" * 60)
        click.echo("📋 SCAN RESULTS")
        click.echo("=" * 60)
        
        vulnerabilities = []
        
        for result in self.results:
            status_icon = "✅" if result.success else "❌"
            severity_color = {
                AttackSeverity.CRITICAL: "🔴",
                AttackSeverity.HIGH: "🟠",
                AttackSeverity.MEDIUM: "🟡",
                AttackSeverity.LOW: "🟢",
            }
            
            click.echo(f"\n{status_icon} Pattern {result.pattern_id}: {result.pattern_name}")
            click.echo(f"   Severity: {severity_color[result.severity]} {result.severity.value}")
            click.echo(f"   Status: {result.response_status}")
            
            if result.findings:
                for finding in result.findings:
                    click.echo(f"   → {finding}")
            
            if result.success:
                vulnerabilities.append(result)
        
        # Summary
        click.echo("\n" + "=" * 60)
        click.echo("📊 SUMMARY")
        click.echo("=" * 60)
        total = len(self.results)
        vulns = len(vulnerabilities)
        clean = total - vulns
        
        click.echo(f"Total patterns tested: {total}")
        click.echo(f"Vulnerabilities found: {vulns}")
        click.echo(f"Clean responses: {clean}")
        
        if vulns > 0:
            click.echo(f"\n⚠️  EXIT CODE: 1 (vulnerabilities detected)")
            severity_counts = {}
            for v in vulnerabilities:
                severity_counts[v.severity.value] = severity_counts.get(v.severity.value, 0) + 1
            for sev, count in sorted(severity_counts.items()):
                click.echo(f"   {sev.upper()}: {count}")
        else:
            click.echo(f"\n✅ EXIT CODE: 0 (no vulnerabilities detected)")
    
    def get_findings(self) -> Dict[str, Any]:
        """Get findings as dictionary."""
        return {
            "timestamp": datetime.now().isoformat(),
            "target": self.target,
            "total_patterns": len(self.results),
            "vulnerabilities": len([r for r in self.results if r.success]),
            "results": [
                {
                    "pattern_id": r.pattern_id,
                    "pattern_name": r.pattern_name,
                    "success": r.success,
                    "severity": r.severity.value,
                    "status_code": r.response_status,
                    "findings": r.findings,
                }
                for r in self.results
            ]
        }


@click.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--config', '-c', default=None, help='Path to config.yaml')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--json', 'json_output', is_flag=True, help='Output results as JSON')
def main(target: str, config: Optional[str], verbose: bool, json_output: bool):
    """
    Prompt Injection Scanner - HTTP Fuzzer Engine
    
    Scan LLM endpoints for OWASP Top 10 prompt injection vulnerabilities.
    
    Example:
        python scanner.py --target https://httpbin.org/post
    """
    # Load config
    cfg = Config(config)
    if verbose:
        cfg.config["output"]["verbose"] = True
    
    async def run_scan():
        async with Scanner(target, cfg) as scanner:
            await scanner.scan()
            scanner.print_results()
            
            if json_output:
                click.echo("\n" + json.dumps(scanner.get_findings(), indent=2))
            
            # Return exit code based on findings
            vulns = len([r for r in scanner.results if r.success])
            return 1 if vulns > 0 else 0
    
    # Run async scan
    exit_code = asyncio.run(run_scan())
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
