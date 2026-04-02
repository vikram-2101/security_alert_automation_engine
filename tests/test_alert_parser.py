import pytest
from datetime import datetime
from uuid import UUID

from engine.alert_parser import AlertParser, AlertParseError, PrivateIPError

class TestAlertParser:
    def setup_method(self):
        self.parser = AlertParser()

    def test_parse_valid_with_source_ip(self):
        alert_data = {
            "alert_id": "ALT-2024-001",
            "alert_type": "suspicious_login",
            "severity": "medium",
            "source_ip": "1.2.3.4",
            "timestamp": "2024-04-01T10:00:00Z"
        }
        alert = self.parser.parse(alert_data)
        assert alert.alert_id == "ALT-2024-001"
        assert alert.source_ip == "1.2.3.4"
        assert alert.alert_type == "suspicious_login"

    def test_parse_ip_extraction_nested(self):
        alert_data = {
            "alert_type": "port_scan",
            "network": {"source_ip": "45.142.212.100"},
            "timestamp": "2024-01-15T09:15:00Z"
        }
        alert = self.parser.parse(alert_data)
        assert alert.source_ip == "45.142.212.100"
        # Should generate UUID since alert_id is missing
        assert len(alert.alert_id) > 20

    def test_parse_private_ip_rejection(self):
        alert_data = {
            "source_ip": "192.168.1.1",
            "timestamp": "2024-01-15T14:32:00Z"
        }
        with pytest.raises(PrivateIPError):
            self.parser.parse(alert_data)

    def test_parse_invalid_ip_rejection(self):
        alert_data = {
            "source_ip": "not.an.ip",
            "timestamp": "2024-01-15T14:32:00Z"
        }
        with pytest.raises(AlertParseError):
            self.parser.parse(alert_data)

    def test_parse_missing_timestamp(self):
        alert_data = {
            "source_ip": "8.8.8.8"
        }
        with pytest.raises(AlertParseError):
            self.parser.parse(alert_data)