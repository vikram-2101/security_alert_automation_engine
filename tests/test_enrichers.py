import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import aiohttp
import os

from engine.enrichers.virustotal import VirusTotalEnricher
from engine.enrichers.abuseipdb import AbuseIPDBEnricher
from engine.enrichers.geolocation import GeolocationEnricher
from data_models import RateLimitError

@pytest.mark.asyncio
class TestVirusTotalEnricher:
    async def setup_method(self):
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': 'test_key'}):
            self.enricher = VirusTotalEnricher()
        self.session = AsyncMock(spec=aiohttp.ClientSession)

    async def test_enrich_success(self):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "harmless": 5},
                    "country": "US",
                    "as_owner": "Google LLC",
                    "reputation": -10
                }
            }
        }
        self.session.get.return_value.__aenter__.return_value = mock_response

        result = await self.enricher.enrich("8.8.8.8", self.session)
        assert result.malicious_score == 50.0
        assert result.not_found == False

    async def test_enrich_404_not_found(self):
        mock_response = AsyncMock()
        mock_response.status = 404
        self.session.get.return_value.__aenter__.return_value = mock_response

        result = await self.enricher.enrich("1.2.3.4", self.session)
        assert result.not_found == True

@pytest.mark.asyncio
class TestAbuseIPDBEnricher:
    async def setup_method(self):
        with patch.dict('os.environ', {'ABUSEIPDB_API_KEY': 'test_key'}):
            self.enricher = AbuseIPDBEnricher()
        self.session = AsyncMock(spec=aiohttp.ClientSession)

    async def test_enrich_success(self):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 100,
                "isTor": True,
                "usageType": "Data Center"
            }
        }
        self.session.get.return_value.__aenter__.return_value = mock_response

        result = await self.enricher.enrich("1.2.3.4", self.session)
        assert result.abuse_confidence_score == 85
        assert result.is_tor == True

@pytest.mark.asyncio
class TestGeolocationEnricher:
    async def setup_method(self):
        self.enricher = GeolocationEnricher()
        self.session = AsyncMock(spec=aiohttp.ClientSession)

    async def test_enrich_success(self):
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json.return_value = {
            "status": "success",
            "country": "USA",
            "proxy": True
        }
        self.session.get.return_value.__aenter__.return_value = mock_response

        result = await self.enricher.enrich("8.8.8.8", self.session)
        assert result.country == "USA"
        assert result.is_proxy == True