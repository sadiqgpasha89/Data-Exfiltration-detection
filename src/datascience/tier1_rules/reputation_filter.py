"""Reputation and Perimeter Policy Filter.

Evaluates egress traffic against:
1. Threat intelligence blacklisted IPs (STIX/TAXII feeds)
2. Malicious Command & Control (C2) domains
3. Zero-tolerance perimeter port rules (e.g. no outbound SSH/RDP from core database subnets)
"""

import ipaddress
import json
from typing import List, Optional, Set, Tuple, Union
from src.core.config import settings


class ReputationFilter:
    """Evaluates destination endpoints and network egress policies."""

    def __init__(self):
        self.malicious_ips: Set[str] = set()
        self.malicious_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self.malicious_domains: Set[str] = set()
        self.prohibited_ports: Set[int] = set()
        self.monitored_subnets: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
        self._load_threat_intel()

    def _load_threat_intel(self):
        path = settings.THREAT_INTEL_IOCS_PATH
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for entry in data.get("malicious_ips", []):
                    if "/" in entry:  # a CIDR block in the feed
                        try:
                            self.malicious_networks.append(ipaddress.ip_network(entry, strict=False))
                        except ValueError:
                            continue
                    else:
                        self.malicious_ips.add(entry)
                self.malicious_domains = {d.lower().rstrip(".") for d in data.get("malicious_domains", [])}
                self.prohibited_ports = set(data.get("prohibited_database_egress_ports", []))
                for subnet_str in data.get("monitored_database_subnets", []):
                    try:
                        self.monitored_subnets.append(ipaddress.ip_network(subnet_str, strict=False))
                    except ValueError:
                        pass

    def is_malicious_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if str(addr) in self.malicious_ips:
            return True
        return any(addr in net for net in self.malicious_networks if net.version == addr.version)

    def is_malicious_domain(self, domain: Optional[str]) -> bool:
        """True when the domain IS a listed domain or a subdomain of one.

        Matching is on whole DNS labels. A plain substring test flags `not-bad.example.community` for a feed entry of
        `bad.example.com` and, worse, `bad.example.com.attacker.org`, which is not under the listed domain at all.
        """
        if not domain:
            return False
        name = domain.lower().rstrip(".")
        return any(name == bad or name.endswith("." + bad) for bad in self.malicious_domains)

    def is_prohibited_database_egress(self, source_ip: str, destination_port: int) -> bool:
        """Enforces zero-tolerance outbound connections on sensitive ports from DB subnets."""
        if destination_port not in self.prohibited_ports:
            return False
        try:
            src_addr = ipaddress.ip_address(source_ip)
        except ValueError:
            return False
        return any(src_addr in subnet for subnet in self.monitored_subnets if subnet.version == src_addr.version)

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
