import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Union
from uuid import uuid4

from data_models import Alert


class AlertParseError(Exception):
    """Raised when alert parsing fails."""
    pass


class PrivateIPError(Exception):
    """Raised when the extracted IP is a private IP."""
    pass


class AlertParser:
    """Parses raw alerts into normalized Alert objects."""

    PRIVATE_IP_RANGES = [
        re.compile(r"^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),  # 10.0.0.0/8
        re.compile(r"^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$"),  # 172.16.0.0/12
        re.compile(r"^192\.168\.\d{1,3}\.\d{1,3}$"),  # 192.168.0.0/16
        re.compile(r"^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),  # 127.0.0.0/8
    ]

    IP_REGEX = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def parse(self, source: Union[str, Path, Dict[str, Any]]) -> Alert:
        """Parse alert from file path, JSON string, or dict.

        Args:
            source: File path, JSON string, or dict containing alert data.

        Returns:
            Alert: Normalized alert object.

        Raises:
            AlertParseError: If parsing fails.
            PrivateIPError: If IP is private.
        """
        if isinstance(source, (str, Path)):
            if Path(source).exists():
                with open(source, 'r') as f:
                    alert_data = json.load(f)
            else:
                alert_data = json.loads(source)
        else:
            alert_data = source

        alert_id = alert_data.get('alert_id') or str(uuid4())
        alert_type = alert_data.get('alert_type', 'unknown')
        severity_input = alert_data.get('severity', 'unknown')
        timestamp_str = alert_data.get('timestamp') or alert_data.get('detected_at') or alert_data.get('first_seen')
        if not timestamp_str:
            raise AlertParseError("Timestamp not found")
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

        source_ip = self._extract_ip(alert_data)
        if not source_ip:
            raise AlertParseError("IP address not found")

        self._validate_ip(source_ip)

        raw = alert_data
        metadata = {k: v for k, v in alert_data.items() if k not in ['alert_id', 'alert_type', 'severity', 'timestamp', 'detected_at', 'first_seen', 'source_ip', 'src_ip', 'ip', 'attacker_ip']}

        return Alert(
            alert_id=alert_id,
            alert_type=alert_type,
            severity_input=severity_input,
            source_ip=source_ip,
            timestamp=timestamp,
            raw=raw,
            metadata=metadata
        )

    def _extract_ip(self, alert_data: Dict[str, Any]) -> str:
        """Extract IP from various possible fields."""
        # Check direct fields
        for field in ['source_ip', 'src_ip', 'ip', 'attacker_ip']:
            if alert_data.get(field):
                return alert_data[field]

        # Check nested fields
        if 'network' in alert_data and alert_data['network'].get('source_ip'):
            return alert_data['network']['source_ip']

        if 'event' in alert_data and alert_data['event'].get('ip_address'):
            return alert_data['event']['ip_address']

        return ""

    def _validate_ip(self, ip: str) -> None:
        """Validate IP format and check for private IPs."""
        if not self.IP_REGEX.match(ip):
            raise AlertParseError(f"Invalid IP address format: {ip}")

        for pattern in self.PRIVATE_IP_RANGES:
            if pattern.match(ip):
                raise PrivateIPError(f"Private IP address rejected: {ip}")