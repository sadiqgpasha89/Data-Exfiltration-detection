"""Sandbox and Forensic File/Process Analysis Tool for Triage Agent."""

import os
from typing import Any, Dict, List
from src.core.telemetry import TelemetryTimer


class SandboxAnalyzerTool:
    """Simulates endpoint file analysis, header inspection, and process tree forensics."""

    def analyze_file_and_process(
        self,
        file_name: str = None,
        process_name: str = None,
        file_hash: str = None,
        entropy: float = 0.0,
    ) -> Dict[str, Any]:
        with TelemetryTimer("sandbox_tool_analysis") as timer:
            findings = {
                "file_analyzed": file_name,
                "process_analyzed": process_name,
                "is_suspicious_process": False,
                "process_parent_tree": [],
                "archive_structure": None,
                "is_encrypted_payload": entropy > 7.5,
                "forensic_notes": [],
            }

            # Process tree heuristics
            if process_name:
                proc = process_name.lower()
                if proc in ["powershell.exe", "cmd.exe", "bash"]:
                    findings["is_suspicious_process"] = True
                    findings["process_parent_tree"] = ["winlogon.exe", "services.exe", "svchost.exe", proc]
                    findings["forensic_notes"].append("Process spawned interactive shell under system service daemon")
                elif proc in ["7z.exe", "rar.exe", "zip.exe"]:
                    findings["is_suspicious_process"] = True
                    findings["process_parent_tree"] = ["explorer.exe", proc]
                    findings["archive_structure"] = "Nested multi-part encrypted archive (.7z.001)"
                    findings["forensic_notes"].append("High-compression AES-256 archive staging detected")
                elif proc in ["pg_dump.exe", "mysqldump.exe", "sqlplus.exe"]:
                    findings["is_suspicious_process"] = True
                    findings["process_parent_tree"] = ["cmd.exe", proc]
                    findings["forensic_notes"].append("Direct relational database dump tool executed")
                else:
                    findings["process_parent_tree"] = ["system", proc]
                    findings["forensic_notes"].append("Process belongs to certified standard enterprise application suite")

            # File header inspection
            if file_name:
                ext = os.path.splitext(file_name)[1].lower()
                if ext in [".sys", ".dll"] and entropy > 7.5:
                    findings["forensic_notes"].append("Masquerading file extension: payload has archive entropy but .dll extension")

        findings["tool_latency_ms"] = round(timer.elapsed_ms, 2)
        return findings


sandbox_tool = SandboxAnalyzerTool()
