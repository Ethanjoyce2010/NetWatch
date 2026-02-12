"""
NetWatch - Network Traffic Anomaly Detector

Monitors live network connections, detects suspicious behaviour,
identifies potentially malicious processes, cross-references against
live threat intelligence feeds, and generates PDF reports.
"""

__version__ = "2.1.0"

from .models import Alert, ConnectionRecord, ProcessProfile, Severity  # noqa: F401
