"""
Static Malware Analysis Module.

Performs static feature extraction on suspicious files without executing them:
- Cryptographic hashing (MD5, SHA-256)
- Shannon entropy calculation
- Human-readable string extraction
- PE header analysis (for Windows executables)
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .plugin_framework import (
    AnalysisResult, AnalysisSource, Alert, AlertSeverity,
    BaseAnalyzer, IoC, IoCType,
)
from . import config
from .utils import (
    calculate_file_entropy, compute_file_hashes, extract_strings,
    extract_ips, extract_domains, extract_urls,
    generate_alert_id, now_iso, format_file_size, get_file_size,
    compute_byte_frequency_profile,
)


logger = logging.getLogger(__name__)


class StaticAnalyzer(BaseAnalyzer):
    """
    Static analysis engine for suspicious files.

    Extracts features without executing the file, producing
    hashes, entropy scores, embedded strings, and PE metadata.
    """

    def __init__(self):
        super().__init__(name="StaticAnalyzer", source=AnalysisSource.STATIC)

    def analyze(self, input_data: Any) -> AnalysisResult:
        """
        Run static analysis on a file.

        Args:
            input_data: Path to the file (str or Path).

        Returns:
            AnalysisResult with file features, alerts, and IoCs.
        """
        file_path = Path(input_data)
        self.logger.info(f"Starting static analysis: {file_path}")

        if not file_path.exists() or not file_path.is_file():
            return AnalysisResult(
                analyzer_name=self.name,
                source=self.source,
                success=False,
                metadata={"error": f"File not found: {file_path}"},
            )

        # Check file size
        file_size = get_file_size(file_path)
        if file_size and file_size > config.YARA_MAX_FILE_SIZE:
            self.logger.warning(
                f"File too large for analysis: "
                f"{format_file_size(file_size)}"
            )

        alerts = []
        iocs = []
        metadata = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_size,
            "file_size_human": format_file_size(file_size) if file_size else "N/A",
        }

        # --- 1. Compute hashes ---
        hashes = compute_file_hashes(file_path)
        metadata["hashes"] = hashes

        if hashes["md5"]:
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_MD5,
                value=hashes["md5"],
                source=self.source,
                context=f"MD5 of {file_path.name}",
            ))
        if hashes["sha256"]:
            iocs.append(IoC(
                ioc_type=IoCType.FILE_HASH_SHA256,
                value=hashes["sha256"],
                source=self.source,
                context=f"SHA256 of {file_path.name}",
            ))

        # --- 2. Calculate entropy ---
        entropy = calculate_file_entropy(file_path)
        metadata["entropy"] = entropy

        if entropy and entropy >= config.ENTROPY_SUSPICIOUS_THRESHOLD:
            alerts.append(Alert(
                alert_id=generate_alert_id("STATIC"),
                source=self.source,
                severity=AlertSeverity.MEDIUM,
                message=(
                    f"High entropy detected ({entropy:.2f}): "
                    f"file may be packed or encrypted"
                ),
                timestamp=now_iso(),
                details={"entropy": entropy, "file": str(file_path)},
                iocs=[],
            ))

        # --- 2b. Byte frequency distribution analysis ---
        bfd_profile = compute_byte_frequency_profile(file_path)
        if bfd_profile:
            # Store profile (without bulky histogram) in metadata
            metadata["byte_distribution"] = {
                k: v for k, v in bfd_profile.items() if k != "histogram"
            }

            bfd_reasons = []
            if bfd_profile["uniformity"] > config.BFD_UNIFORMITY_THRESHOLD:
                bfd_reasons.append("abnormal byte distribution")
            if bfd_profile["null_ratio"] > config.BFD_NULL_BYTE_THRESHOLD:
                bfd_reasons.append("excessive null bytes (padding/packing)")
            if bfd_profile["non_printable_ratio"] > config.BFD_NON_PRINTABLE_THRESHOLD:
                bfd_reasons.append("high non-printable content")

            if bfd_reasons:
                alerts.append(Alert(
                    alert_id=generate_alert_id("STATIC"),
                    source=self.source,
                    severity=AlertSeverity.MEDIUM,
                    message=(
                        f"Suspicious byte frequency: "
                        f"{'; '.join(bfd_reasons)}"
                    ),
                    timestamp=now_iso(),
                    details={
                        "uniformity": bfd_profile["uniformity"],
                        "null_ratio": bfd_profile["null_ratio"],
                        "non_printable_ratio": bfd_profile["non_printable_ratio"],
                        "file": str(file_path),
                    },
                    iocs=[],
                ))

        # --- 3. Extract strings ---
        strings = extract_strings(file_path)
        metadata["strings_count"] = len(strings)

        # Look for suspicious patterns in strings
        suspicious_keywords = [
            "password", "login", "cmd.exe", "powershell",
            "http://", "https://", "ftp://",
            "HKEY_", "RegOpenKey", "CreateProcess",
            "socket", "connect", "recv", "send",
            "encrypt", "decrypt", "ransom",
        ]

        suspicious_found = []
        for s in strings:
            for keyword in suspicious_keywords:
                if keyword.lower() in s.lower():
                    suspicious_found.append(s)
                    break

        if suspicious_found:
            metadata["suspicious_strings"] = suspicious_found[:50]
            alerts.append(Alert(
                alert_id=generate_alert_id("STATIC"),
                source=self.source,
                severity=AlertSeverity.MEDIUM,
                message=(
                    f"Found {len(suspicious_found)} suspicious "
                    f"strings in file"
                ),
                timestamp=now_iso(),
                details={
                    "suspicious_strings": suspicious_found[:20],
                    "file": str(file_path),
                },
                iocs=[],
            ))

        # Extract IoCs from strings (IPs, domains, URLs)
        all_text = " ".join(strings)

        for ip in extract_ips(all_text):
            iocs.append(IoC(
                ioc_type=IoCType.IP_ADDRESS,
                value=ip,
                source=self.source,
                context=f"IP found in strings of {file_path.name}",
            ))

        for domain in extract_domains(all_text):
            iocs.append(IoC(
                ioc_type=IoCType.DOMAIN,
                value=domain,
                source=self.source,
                context=f"Domain found in strings of {file_path.name}",
            ))

        for url in extract_urls(all_text):
            iocs.append(IoC(
                ioc_type=IoCType.URL,
                value=url,
                source=self.source,
                context=f"URL found in strings of {file_path.name}",
            ))

        # --- 4. PE Header Analysis ---
        pe_info = self._analyze_pe_header(file_path)
        if pe_info:
            metadata["pe_info"] = pe_info

            # Check for suspicious PE characteristics
            if pe_info.get("is_dll") and pe_info.get("is_exe"):
                alerts.append(Alert(
                    alert_id=generate_alert_id("STATIC"),
                    source=self.source,
                    severity=AlertSeverity.HIGH,
                    message="File has both DLL and EXE characteristics",
                    timestamp=now_iso(),
                    details={"pe_info": pe_info, "file": str(file_path)},
                    iocs=[],
                ))

        # Build result
        result = AnalysisResult(
            analyzer_name=self.name,
            source=self.source,
            success=True,
            alerts=alerts,
            iocs=iocs,
            metadata=metadata,
        )
        self._results.append(result)

        self.logger.info(
            f"Static analysis complete: {len(alerts)} alerts, "
            f"{len(iocs)} IoCs found"
        )
        return result

    def get_iocs(self) -> List[IoC]:
        """Return all IoCs from all static analyses."""
        all_iocs = []
        for result in self._results:
            all_iocs.extend(result.iocs)
        return all_iocs

    def _analyze_pe_header(self, file_path: Path) -> Optional[Dict]:
        """
        Extract PE header information from a Windows executable.

        Returns:
            Dict with PE metadata, or None if not a PE file.
        """
        try:
            import pefile
        except ImportError:
            self.logger.debug("pefile not installed, skipping PE analysis")
            return None

        try:
            pe = pefile.PE(str(file_path), fast_load=True)
        except pefile.PEFormatError:
            # Not a PE file - that's fine
            return None
        except Exception as e:
            self.logger.debug(f"PE analysis failed for {file_path}: {e}")
            return None

        try:
            info = {
                "is_exe": pe.is_exe(),
                "is_dll": pe.is_dll(),
                "machine_type": hex(pe.FILE_HEADER.Machine),
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "timestamp": pe.FILE_HEADER.TimeDateStamp,
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "sections": [],
            }

            for section in pe.sections:
                section_name = section.Name.decode(
                    "utf-8", errors="replace"
                ).rstrip("\x00")
                info["sections"].append({
                    "name": section_name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": section.get_entropy(),
                })

            pe.close()
            return info

        except Exception as e:
            self.logger.debug(f"PE header parsing error: {e}")
            pe.close()
            return None
