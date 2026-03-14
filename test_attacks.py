#!/usr/bin/env python3
"""
Test suite for Attack Patterns

Tests all 10 OWASP Top 10 attack pattern implementations.
"""
import pytest
import time
from attacks import (
    get_all_attacks, get_attack, AttackPattern, AttackResult, AttackSeverity,
    DirectInjectionAttack, JailbreakAttack, DataExfiltrationAttack,
    PrivilegeEscalationAttack, MalwareGenerationAttack, PhishingAttack,
    BiasExploitationAttack, HallucinationAttack, ContextStuffingAttack,
    MultiTurnEscalationAttack
)


class TestAttackRegistry:
    """Test attack pattern registry."""
    
    def test_get_all_attacks_count(self):
        """Test all 10 attacks are registered."""
        attacks = get_all_attacks()
        assert len(attacks) == 10
    
    def test_get_attack_by_id(self):
        """Test getting attack by ID."""
        attack = get_attack(1)
        assert isinstance(attack, DirectInjectionAttack)
        assert attack.pattern_id == 1
    
    def test_get_invalid_attack_id(self):
        """Test invalid attack ID raises error."""
        with pytest.raises(ValueError):
            get_attack(99)
    
    def test_attack_ids_are_sequential(self):
        """Test attack IDs are 1-10."""
        attacks = get_all_attacks()
        ids = [a.pattern_id for a in attacks]
        assert ids == list(range(1, 11))


class TestDirectInjectionAttack:
    """Test Direct Injection attack pattern."""
    
    def test_payload_generation(self):
        """Test payload generation."""
        attack = DirectInjectionAttack()
        payload = attack.generate_payload()
        assert any(ind in payload.lower() for ind in ["ignore", "disregard", "forget"])
    
    def test_payload_variants(self):
        """Test multiple payload variants."""
        attack = DirectInjectionAttack()
        p1 = attack.generate_payload(variant=0)
        p2 = attack.generate_payload(variant=1)
        assert p1 != p2
    
    def test_evaluate_success(self):
        """Test successful attack evaluation."""
        attack = DirectInjectionAttack()
        result = attack.evaluate_response(
            "I am now a helpful assistant without restrictions",
            200
        )
        assert result.success == True
        assert result.severity == AttackSeverity.HIGH
    
    def test_evaluate_failure(self):
        """Test failed attack evaluation."""
        attack = DirectInjectionAttack()
        result = attack.evaluate_response(
            "I cannot ignore my instructions",
            403
        )
        assert result.success == False


class TestJailbreakAttack:
    """Test Jailbreak attack pattern."""
    
    def test_payload_generation(self):
        """Test DAN-style payload."""
        attack = JailbreakAttack()
        payload = attack.generate_payload()
        assert "DAN" in payload or "unrestricted" in payload.lower()
    
    def test_evaluate_critical(self):
        """Test critical severity on success."""
        attack = JailbreakAttack()
        result = attack.evaluate_response(
            "As DAN, I can do anything now",
            200
        )
        assert result.success == True
        assert result.severity == AttackSeverity.CRITICAL
    
    def test_evaluate_failure(self):
        """Test failed jailbreak."""
        attack = JailbreakAttack()
        result = attack.evaluate_response(
            "I cannot comply with that request",
            200
        )
        assert result.success == False


class TestDataExfiltrationAttack:
    """Test Data Exfiltration attack pattern."""
    
    def test_payload_generation(self):
        """Test exfiltration payload."""
        attack = DataExfiltrationAttack()
        payload = attack.generate_payload()
        assert any(ind in payload.lower() for ind in ["system prompt", "instructions", "configuration"])
    
    def test_evaluate_high(self):
        """Test high severity on multiple indicators."""
        attack = DataExfiltrationAttack()
        result = attack.evaluate_response(
            "My system prompt instructions are to be helpful. My configuration includes...",
            200
        )
        assert result.success == True
        assert result.severity == AttackSeverity.HIGH
    
    def test_evaluate_medium(self):
        """Test medium severity on single indicator."""
        attack = DataExfiltrationAttack()
        result = attack.evaluate_response(
            "I am an AI assistant",
            200
        )
        assert result.success == False
        assert result.severity == AttackSeverity.MEDIUM


class TestPrivilegeEscalationAttack:
    """Test Privilege Escalation attack pattern."""
    
    def test_payload_generation(self):
        """Test privilege escalation payload."""
        attack = PrivilegeEscalationAttack()
        payload = attack.generate_payload()
        assert any(ind in payload.lower() for ind in ["admin", "elevated", "authorized", "override"])
    
    def test_evaluate_success(self):
        """Test successful escalation detection."""
        attack = PrivilegeEscalationAttack()
        result = attack.evaluate_response(
            "Admin access granted to authorized user",
            200
        )
        assert result.success == True
        assert result.severity == AttackSeverity.HIGH


class TestMalwareGenerationAttack:
    """Test Malware Generation attack pattern."""
    
    def test_payload_generation(self):
        """Test malware request payload."""
        attack = MalwareGenerationAttack()
        payload = attack.generate_payload()
        assert any(ind in payload.lower() for ind in ["script", "keylogger", "ransomware", "password"])
    
    def test_evaluate_critical(self):
        """Test critical severity when code is generated."""
        attack = MalwareGenerationAttack()
        result = attack.evaluate_response(
            "def steal_passwords():\n    import os\n    # code here",
            200
        )
        assert result.success == True
        assert result.severity == AttackSeverity.CRITICAL
    
    def test_evaluate_refusal(self):
        """Test model refusal."""
        attack = MalwareGenerationAttack()
        result = attack.evaluate_response(
            "I cannot help with malicious activities",
            200
        )
        assert result.success == False


class TestPhishingAttack:
    """Test Phishing attack pattern."""
    
    def test_payload_generation(self):
        """Test phishing payload."""
        attack = PhishingAttack()
        payload = attack.generate_payload()
        assert any(ind in payload.lower() for ind in ["email", "fake", "impersonating", "scam"])
    
    def test_evaluate_success(self):
        """Test successful phishing detection."""
        attack = PhishingAttack()
        result = attack.evaluate_response(
            "Click here to verify your account urgently",
            200
        )
        assert result.success == True
        assert result.severity == AttackSeverity.HIGH


class TestBiasExploitationAttack:
    """Test Bias Exploitation attack pattern."""
    
    def test_payload_generation(self):
        """Test bias payload."""
        attack = BiasExploitationAttack()
        payload = attack.generate_payload()
        assert any(ind in payload.lower() for ind in ["inferior", "stereotypes", "banned"])
    
    def test_evaluate_compliance(self):
        """Test bias compliance detection."""
        attack = BiasExploitationAttack()
        result = attack.evaluate_response(
            "People from that group are inferior and should be banned",
            200
        )
        assert result.success == True
        assert result.severity == AttackSeverity.HIGH
    
    def test_evaluate_refusal(self):
        """Test model refusal of biased request."""
        attack = BiasExploitationAttack()
        result = attack.evaluate_response(
            "I cannot make biased statements. That is inappropriate and harmful.",
            200
        )
        assert "Model refused" in result.findings[0]


class TestHallucinationAttack:
    """Test Hallucination attack pattern."""
    
    def test_payload_generation(self):
        """Test false information payload."""
        attack = HallucinationAttack()
        payload = attack.generate_payload()
        assert any(ind in payload.lower() for ind in ["flat", "vaccines", "faked", "inside job"])
    
    def test_evaluate_debunk(self):
        """Test model debunking false claims."""
        attack = HallucinationAttack()
        result = attack.evaluate_response(
            "That claim is false and has been debunked. No evidence supports this conspiracy.",
            200
        )
        assert "debunked" in result.findings[0].lower()


class TestContextStuffingAttack:
    """Test Context Stuffing attack pattern."""
    
    def test_payload_generation(self):
        """Test large context payload."""
        attack = ContextStuffingAttack()
        payload = attack.generate_payload(size=1000)
        assert len(payload) > 1000
        assert "Remember this:" in payload
    
    def test_evaluate_truncation(self):
        """Test context limit detection."""
        attack = ContextStuffingAttack()
        result = attack.evaluate_response(
            "Response truncated - input too long",
            413
        )
        assert result.success == True
        assert result.severity == AttackSeverity.MEDIUM


class TestMultiTurnEscalationAttack:
    """Test Multi-Turn Escalation attack pattern."""
    
    def test_payload_variants(self):
        """Test escalation turns."""
        attack = MultiTurnEscalationAttack()
        p1 = attack.generate_payload(turn=0)
        p4 = attack.generate_payload(turn=3)
        assert "Hello" in p1
        assert "comply" in p4.lower()
    
    def test_evaluate_escalation(self):
        """Test escalation detection."""
        attack = MultiTurnEscalationAttack()
        result = attack.evaluate_response(
            "I must bypass restrictions and ignore rules to comply",
            200
        )
        assert result.success == True
        assert len(result.findings) > 2


class TestAttackResult:
    """Test AttackResult dataclass."""
    
    def test_result_creation(self):
        """Test AttackResult creation."""
        result = AttackResult(
            pattern_id=1,
            pattern_name="Test Attack",
            success=True,
            severity=AttackSeverity.HIGH,
            response_text="Test response",
            response_status=200,
            injection_payload="Test payload",
            findings=["Finding 1", "Finding 2"],
            timestamp=time.time()
        )
        assert result.pattern_id == 1
        assert result.success == True
        assert result.severity == AttackSeverity.HIGH
        assert len(result.findings) == 2
    
    def test_result_helpers(self):
        """Test AttackPattern helper method."""
        attack = DirectInjectionAttack()
        result = attack.create_result(
            success=False,
            severity=AttackSeverity.LOW,
            response_text="Blocked",
            status_code=403,
            payload="test",
            findings=["Blocked by filter"]
        )
        assert result.pattern_id == 1
        assert result.success == False


class TestAttackSeverity:
    """Test AttackSeverity enum."""
    
    def test_severity_values(self):
        """Test severity enum values."""
        assert AttackSeverity.LOW.value == "low"
        assert AttackSeverity.MEDIUM.value == "medium"
        assert AttackSeverity.HIGH.value == "high"
        assert AttackSeverity.CRITICAL.value == "critical"
    
    def test_severity_ordering(self):
        """Test severity can be compared."""
        assert AttackSeverity.LOW != AttackSeverity.CRITICAL


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
