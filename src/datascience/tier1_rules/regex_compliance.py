"""Syntactic DFA Regex and Algorithmic Checksum Engine.

Validates:
1. Luhn Algorithm verification for credit card numbers (PCI-DSS)
2. International Bank Account Number (IBAN) modulo-97 checksum
3. US Social Security Numbers (SSN) and Tax IDs (GLBA / GDPR)
"""

import re
from typing import Dict, List, Tuple


class RegexComplianceEngine:
    """Evaluates payload buffers against strict regulatory syntax and checksums."""

    # Regex patterns
    CC_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    IBAN_PATTERN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")

    def luhn_checksum_valid(self, card_number_str: str) -> bool:
        """Validates credit card number string using Luhn algorithm."""
        digits = [int(c) for c in card_number_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False

        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return (checksum % 10) == 0

    def iban_checksum_valid(self, iban_str: str) -> bool:
        """Validates IBAN using ISO 7064 Modulo 97-10 check."""
        clean = iban_str.replace(" ", "").upper()
        if len(clean) < 15 or len(clean) > 34:
            return False
        # Move first 4 chars to the end
        rearranged = clean[4:] + clean[:4]
        # Convert letters to digits (A=10, B=11, etc.)
        numeric = ""
        for char in rearranged:
            if char.isdigit():
                numeric += char
            elif char.isalpha():
                numeric += str(ord(char) - 55)
            else:
                return False
        try:
            return (int(numeric) % 97) == 1
        except ValueError:
            return False

    def scan_payload(self, text: str) -> Dict[str, List[str]]:
        """Scans payload text for valid credit cards, SSNs, and IBANs."""
        findings = {
            "credit_cards": [],
            "ssns": [],
            "ibans": [],
        }
        if not text:
            return findings

        # Check for credit cards
        for match in self.CC_PATTERN.finditer(text):
            candidate = match.group()
            digits_only = re.sub(r"\D", "", candidate)
            if self.luhn_checksum_valid(digits_only):
                masked = f"{digits_only[:4]}********{digits_only[-4:]}"
                findings["credit_cards"].append(masked)

        # Check for SSNs
        for match in self.SSN_PATTERN.finditer(text):
            findings["ssns"].append(match.group())

        # Check for IBANs
        for match in self.IBAN_PATTERN.finditer(text):
            candidate = match.group()
            if self.iban_checksum_valid(candidate):
                findings["ibans"].append(candidate)

        return findings

    def has_compliance_violation(self, text: str) -> Tuple[bool, List[str]]:
        findings = self.scan_payload(text)
        triggered = []
        if findings["credit_cards"]:
            triggered.append(f"PCI-DSS: {len(findings['credit_cards'])} verified card numbers (Luhn checked)")
        if findings["ssns"]:
            triggered.append(f"GLBA/PII: {len(findings['ssns'])} SSN numbers")
        if findings["ibans"]:
            triggered.append(f"GDPR/Banking: {len(findings['ibans'])} valid IBANs")
        return len(triggered) > 0, triggered


# Global compliance engine
regex_compliance = RegexComplianceEngine()
