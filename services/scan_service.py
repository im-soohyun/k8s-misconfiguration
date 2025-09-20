import os
import re
from typing import Dict, Iterable, List, Tuple


class ScanService:
    """Scans files for risky Kubernetes configuration patterns.

    The scanner searches line-by-line with whitespace-tolerant regexes.
    It focuses on common K8s YAML/JSON files.
    """

    SUPPORTED_EXTENSIONS = {".yaml", ".yml", ".json"}
    SKIP_DIR_NAMES = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "__pycache__"}

    def __init__(self) -> None:
        self.patterns: Dict[str, re.Pattern[str]] = {
            "privileged_true": re.compile(r"\bprivileged\s*:\s*true\b", re.IGNORECASE),
            "hostNetwork_true": re.compile(r"\bhostNetwork\s*:\s*true\b", re.IGNORECASE),
            "hostPID_true": re.compile(r"\bhostPID\s*:\s*true\b", re.IGNORECASE),
            "hostIPC_true": re.compile(r"\bhostIPC\s*:\s*true\b", re.IGNORECASE),
            "allowPrivilegeEscalation_true": re.compile(r"\ballowPrivilegeEscalation\s*:\s*true\b", re.IGNORECASE),
            "runAsNonRoot_false": re.compile(r"\brunAsNonRoot\s*:\s*false\b", re.IGNORECASE),
            "runAsUser_root": re.compile(r"\brunAsUser\s*:\s*0\b", re.IGNORECASE),
            "runAsGroup_root": re.compile(r"\brunAsGroup\s*:\s*0\b", re.IGNORECASE),
            "readOnlyRootFilesystem_false": re.compile(r"\breadOnlyRootFilesystem\s*:\s*false\b", re.IGNORECASE),
            "automountServiceAccountToken_true": re.compile(r"\bautomountServiceAccountToken\s*:\s*true\b", re.IGNORECASE),
            "serviceAccountName_default": re.compile(r"\bserviceAccountName\s*:\s*default\b", re.IGNORECASE),
            "hostPath_used": re.compile(r"\bhostPath\s*:\s*", re.IGNORECASE),
            "service_type_NodePort": re.compile(r"\btype\s*:\s*NodePort\b", re.IGNORECASE),
            "hostPort_used": re.compile(r"\bhostPort\s*:\s*\d+\b", re.IGNORECASE),
            "shareProcessNamespace_true": re.compile(r"\bshareProcessNamespace\s*:\s*true\b", re.IGNORECASE),
            "dnsPolicy_ClusterFirstWithHostNet": re.compile(r"\bdnsPolicy\s*:\s*ClusterFirstWithHostNet\b", re.IGNORECASE),
            "seccompProfile_Unconfined": re.compile(r"\bseccompProfile\s*:\s*\{?[^\n\}]*type\s*:\s*Unconfined\b", re.IGNORECASE),
            "apparmor_unconfined": re.compile(r"apparmor\.security\.beta\.kubernetes\.io/[^:\n]+\s*:\s*unconfined\b", re.IGNORECASE),
            # Same-line capabilities add list
            "capabilities_add_sysadmin_inline": re.compile(
                r"capabilities\s*:\s*\{?[^\n\}]*add\s*:\s*\[[^\]]*(SYS_ADMIN|ALL|NET_ADMIN)[^\]]*\]",
                re.IGNORECASE,
            ),
            # procMount: Unmasked
            "procMount_Unmasked": re.compile(r"\bprocMount\s*:\s*Unmasked\b", re.IGNORECASE),
        }

    def _is_supported_file(self, file_path: str) -> bool:
        _, ext = os.path.splitext(file_path)
        return ext in self.SUPPORTED_EXTENSIONS

    def _scan_file_lines(self, file_path: str) -> Iterable[Tuple[int, str]]:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, start=1):
                    yield idx, line.rstrip("\n")
        except Exception:
            return

    def _scan_capabilities_multiline(self, file_path: str) -> List[Dict[str, object]]:
        findings: List[Dict[str, object]] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return findings

        in_capabilities_block = False
        saw_add = False
        block_indent = None
        for line_number, raw in enumerate(lines, start=1):
            line = raw.rstrip("\n")
            stripped = line.lstrip()
            indent = len(line) - len(stripped)

            # Exit block when indentation decreases
            if block_indent is not None and indent <= block_indent and not stripped.startswith("-"):
                in_capabilities_block = False
                saw_add = False
                block_indent = None

            if re.search(r"\bcapabilities\s*:\s*", stripped, flags=re.IGNORECASE):
                in_capabilities_block = True
                block_indent = indent
                saw_add = False
                continue

            if in_capabilities_block and re.search(r"\badd\s*:\s*", stripped, flags=re.IGNORECASE):
                saw_add = True
                continue

            if in_capabilities_block and saw_add:
                if re.search(r"\b(SYS_ADMIN|ALL|NET_ADMIN)\b", stripped, flags=re.IGNORECASE):
                    findings.append({
                        "filePath": file_path,
                        "lineNumber": line_number,
                        "ruleId": "capabilities_add_privileged_caps",
                        "matchedText": stripped.strip(),
                    })
        return findings

    def scan_repository(self, repo_root: str) -> Dict[str, object]:
        findings: List[Dict[str, object]] = []
        files_scanned = 0

        for root, dirs, files in os.walk(repo_root):
            # Prune noisy/irrelevant directories
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIR_NAMES]

            for name in files:
                path = os.path.join(root, name)
                if not self._is_supported_file(path):
                    continue
                files_scanned += 1

                # Line-by-line regex patterns
                for line_number, line in self._scan_file_lines(path):
                    for rule_id, pattern in self.patterns.items():
                        if rule_id.startswith("capabilities_add_sysadmin_inline"):
                            # Handled below with full-line content
                            continue
                        if pattern.search(line):
                            findings.append({
                                "filePath": path,
                                "lineNumber": line_number,
                                "ruleId": rule_id,
                                "matchedText": line.strip(),
                            })

                # Inline capabilities add list
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    inline_pat = self.patterns["capabilities_add_sysadmin_inline"]
                    for match in inline_pat.finditer(content):
                        # Compute line by counting newlines up to match.start()
                        prefix = content[: match.start()]
                        line_number = prefix.count("\n") + 1
                        matched_line = content.splitlines()[line_number - 1] if content.splitlines() else ""
                        findings.append({
                            "filePath": path,
                            "lineNumber": line_number,
                            "ruleId": "capabilities_add_sysadmin_inline",
                            "matchedText": matched_line.strip(),
                        })
                except Exception:
                    pass

                # Multiline capabilities block (capabilities -> add -> - SYS_ADMIN|ALL|NET_ADMIN)
                findings.extend(self._scan_capabilities_multiline(path))

        return {
            "filesScanned": files_scanned,
            "findings": findings,
        }
