"""LLMOps Prompt Registry & Versioning Manager.

Maintains cryptographically anchored system prompt templates, guardrails,
and structured output JSON schemas for the multi-agent swarm.
"""

import hashlib
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PromptTemplate(BaseModel):
    template_id: str
    agent_name: str
    version: str
    system_prompt: str
    temperature: float = 0.1
    schema_definition: Dict[str, Any] = Field(default_factory=dict)
    sha256_checksum: str = ""

    def model_post_init(self, __context):
        if not self.sha256_checksum:
            self.sha256_checksum = hashlib.sha256(self.system_prompt.encode()).hexdigest()


class PromptManager:
    """Versioned prompt repository with validation guardrails."""

    def __init__(self):
        self.prompts: Dict[str, PromptTemplate] = {}
        self._register_default_prompts()

    def _register_default_prompts(self):
        self.register_prompt(
            PromptTemplate(
                template_id="pmt-triage-v1.3",
                agent_name="TriageAgent",
                version="1.3.0",
                system_prompt=(
                    "You are the Tier-1 Forensic Triage Agent for a Tier-1 Investment Bank. "
                    "Analyze file headers, entropy, and process parent-child trees. "
                    "Identify obfuscated archives, steganographic payloads, and suspicious shells."
                ),
                temperature=0.0,
            )
        )
        self.register_prompt(
            PromptTemplate(
                template_id="pmt-correlation-v2.0",
                agent_name="CorrelationAgent",
                version="2.0.1",
                system_prompt=(
                    "You are the Context & Correlation Agent powered by Enterprise Graph-RAG. "
                    "Query Active Directory, HR records, and Jira ITSM tickets. "
                    "Determine if bulk data extractions possess verified digital authorizations."
                ),
                temperature=0.1,
            )
        )
        self.register_prompt(
            PromptTemplate(
                template_id="pmt-compliance-v1.2",
                agent_name="ComplianceAuditorAgent",
                version="1.2.0",
                system_prompt=(
                    "You are the Banking Policy & Compliance Auditor Agent. "
                    "Map observed security violations to PCI-DSS v4.0, GDPR, GLBA, and BCBS 239. "
                    "Establish statutory reporting timelines and regulatory capital risk."
                ),
                temperature=0.0,
            )
        )
        self.register_prompt(
            PromptTemplate(
                template_id="pmt-orchestrator-v3.1",
                agent_name="SwarmOrchestrator",
                version="3.1.0",
                system_prompt=(
                    "You are the Multi-Agent Swarm Orchestrator. "
                    "Conduct structured hypothesis debate, synthesize disparate agent findings, "
                    "calculate consensus risk, and generate cryptographically signed incident dossiers."
                ),
                temperature=0.1,
            )
        )

    def register_prompt(self, prompt: PromptTemplate):
        self.prompts[prompt.template_id] = prompt

    def get_prompt(self, template_id: str) -> Optional[PromptTemplate]:
        return self.prompts.get(template_id)

    def get_all_prompts(self) -> List[PromptTemplate]:
        return list(self.prompts.values())


prompt_manager = PromptManager()
