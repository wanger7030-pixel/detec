"""
Extensible Plugin Framework for the Integrated Detection System.

Provides abstract base classes and a dynamic plugin loader to allow
seamless integration of new detection rules or analysis modules.
This satisfies requirement 11: extensible rule/plugin framework.
"""

import importlib
import inspect
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


# ============================================================================
# Data Models
# ============================================================================

class IoCType(Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE_HASH_MD5 = "file_hash_md5"
    FILE_HASH_SHA256 = "file_hash_sha256"
    URL = "url"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisSource(Enum):
    """Identifies which analyzer produced the result."""
    SNORT = "snort"
    YARA = "yara"
    STATIC = "static"
    DYNAMIC_CAPE = "dynamic_cape"
    CUSTOM = "custom"


@dataclass
class IoC:
    """Represents a single Indicator of Compromise."""
    ioc_type: IoCType
    value: str
    source: AnalysisSource
    confidence: float = 1.0
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.ioc_type.value,
            "value": self.value,
            "source": self.source.value,
            "confidence": self.confidence,
            "context": self.context,
        }


@dataclass
class Alert:
    """Represents a detection alert from any analyzer."""
    alert_id: str
    source: AnalysisSource
    severity: AlertSeverity
    message: str
    timestamp: str
    details: Dict[str, Any] = field(default_factory=dict)
    iocs: List[IoC] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "source": self.source.value,
            "severity": self.severity.value,
            "message": self.message,
            "timestamp": self.timestamp,
            "details": self.details,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
        }


@dataclass
class AnalysisResult:
    """Unified result container returned by all analyzers."""
    analyzer_name: str
    source: AnalysisSource
    success: bool
    alerts: List[Alert] = field(default_factory=list)
    iocs: List[IoC] = field(default_factory=list)
    raw_output: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "analyzer_name": self.analyzer_name,
            "source": self.source.value,
            "success": self.success,
            "alerts": [a.to_dict() for a in self.alerts],
            "iocs": [i.to_dict() for i in self.iocs],
            "metadata": self.metadata,
        }


# ============================================================================
# Abstract Base Class - All analyzers must implement this
# ============================================================================

class BaseAnalyzer(ABC):
    """
    Abstract base class defining the interface for all analysis plugins.

    Every analyzer (Snort, YARA, CAPEv2, or future custom modules)
    must extend this class and implement analyze() and get_iocs().
    """

    def __init__(self, name: str, source: AnalysisSource):
        self.name = name
        self.source = source
        self._results: List[AnalysisResult] = []
        self.logger = logging.getLogger(f"{__name__}.{name}")

    @abstractmethod
    def analyze(self, input_data: Any) -> AnalysisResult:
        """
        Run analysis on the provided input data.

        Args:
            input_data: Input specific to the analyzer type.
                       - SnortAnalyzer: path to PCAP file
                       - YaraAnalyzer: path to file or directory
                       - CapeAnalyzer: path to malware sample
                       - StaticAnalyzer: path to file

        Returns:
            AnalysisResult with alerts and IoCs.
        """
        pass

    @abstractmethod
    def get_iocs(self) -> List[IoC]:
        """
        Return all IoCs discovered across all analyses.

        Returns:
            List of IoC objects.
        """
        pass

    def get_results(self) -> List[AnalysisResult]:
        """Return all stored analysis results."""
        return self._results

    def clear_results(self):
        """Clear stored results for a fresh analysis run."""
        self._results.clear()

    def is_available(self) -> bool:
        """
        Check if this analyzer's dependencies are available.
        Override this to add custom availability checks (e.g., is Snort installed?).
        """
        return True


# ============================================================================
# Plugin Loader - Dynamic module loading for extensibility
# ============================================================================

class PluginLoader:
    """
    Dynamically discovers and loads analyzer plugins.

    Scans a directory for Python modules containing classes that
    extend BaseAnalyzer, enabling hot-pluggable analysis modules.
    """

    def __init__(self):
        self._plugins: Dict[str, type] = {}
        self._instances: Dict[str, BaseAnalyzer] = {}

    def discover_plugins(self, plugin_dir: Path) -> List[str]:
        """
        Scan a directory for Python files containing BaseAnalyzer subclasses.

        Args:
            plugin_dir: Directory to scan for .py plugin files.

        Returns:
            List of discovered plugin names.
        """
        discovered = []

        if not plugin_dir.exists():
            self.logger_warn(f"Plugin directory does not exist: {plugin_dir}")
            return discovered

        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue

            try:
                module_name = py_file.stem
                spec = importlib.util.spec_from_file_location(
                    module_name, py_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find all BaseAnalyzer subclasses in the module
                for attr_name, attr_value in inspect.getmembers(module):
                    if (inspect.isclass(attr_value)
                            and issubclass(attr_value, BaseAnalyzer)
                            and attr_value is not BaseAnalyzer):
                        self._plugins[attr_name] = attr_value
                        discovered.append(attr_name)
                        logger.info(f"Discovered plugin: {attr_name}")

            except Exception as e:
                logger.error(f"Failed to load plugin from {py_file}: {e}")

        return discovered

    def register_plugin(self, name: str, plugin_class: type):
        """Manually register a plugin class."""
        if not issubclass(plugin_class, BaseAnalyzer):
            raise TypeError(
                f"{plugin_class} must be a subclass of BaseAnalyzer"
            )
        self._plugins[name] = plugin_class
        logger.info(f"Registered plugin: {name}")

    def create_instance(self, name: str, **kwargs) -> BaseAnalyzer:
        """Create an instance of a registered plugin."""
        if name not in self._plugins:
            raise KeyError(f"Plugin '{name}' not registered")

        instance = self._plugins[name](**kwargs)
        self._instances[name] = instance
        return instance

    def get_all_instances(self) -> Dict[str, BaseAnalyzer]:
        """Return all created plugin instances."""
        return self._instances

    @staticmethod
    def logger_warn(msg):
        logger.warning(msg)
