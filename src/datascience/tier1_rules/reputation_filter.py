"""Reputation and Perimeter Policy Filter.

Evaluates egress traffic against:
1. Threat intelligence blacklisted IPs (STIX/TAXII feeds)
2. Malicious Command & Control (C2) domains
3. Zero-tolerance perimeter port rules (e.g. no outbound SSH/RDP from core database subnets)
"""

import ipaddress
import json
from typing import List, Set, Tuple
from src.core.config import settings


class ReputationFilter:
    """Evaluates destination endpoints and network egress policies."""

    def __init__(self):
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.prohibited_ports: Set[int] = set()
        self.monitored_subnets: List[ipaddress.IPv4Network] = []
        self._load_threat_intel()

    def _load_threat_intel(self):
        path = settings.THREAT_INTEL_IOCS_PATH
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.malicious_ips = set(data.get("malicious_ips", []))
                self.malicious_domains = set(data.get("malicious_domains", []))
                self.prohibited_ports = set(data.get("prohibited_database_egress_ports", []))
                for subnet_str in data.get("monitored_database_subnets", []):
                    try:
                        self.monitored_subnets.append(ipaddress.IPv4Network(subnet_str))
                    except ValueError:
                        pass

    def is_malicious_ip(self, ip: str) -> bool:
        return ip in self.malicious_ips

    def is_malicious_domain(self, domain: str) -> bool:
        if not domain:
            return False
        domain_lower = domain.lower()
        for bad in self.malicious_domains:
            if bad in domain_lower:
                return True
        return False

    def is_prohibited_database_egress(self, source_ip: str, destination_port: int) -> bool:
        """Enforces zero-tolerance outbound connections on sensitive ports from DB subnets."""
        if destination_port not in self.prohibited_ports:
            return False
        try:
            src_addr = ipaddress.IPv4Address(source_ip)
            for subnet in self.monitored_subnets:
                if src_addr in subnet:
                    return True
        except ValueError:
            pass
        return False

    def evaluate_connection(
        self, source_ip: str, destination_ip: str, destination_port: int, domain_queried: str = None
    ) -> Tuple[bool, List[str]]:
        """Returns (is_violation, list_of_reasons)."""
        violations = []
        if self.is_malicious_ip(destination_ip):
            violations.append(f"Destination IP {destination_ip} matched Threat Intel C2 Blacklist")

        if domain_queried and self.is_malicious_domain(domain_queried):
            violations.append(f"Domain {domain_queried} matched C2 / Exfiltration Tunnel feed")

        if self.is_prohibited_database_egress(source_ip, destination_port):
            violations.append(f"Zero-tolerance egress port {destination_port} from DB subnet {source_ip}")

        return len(violations) > 0, violations


# Global reputation filter
reputation_filter = ReputationFilter()
