"""Tests for convert_cpe.py — NVD CPE Dictionary JSON → SPO triples converter."""

import json

import pytest

from convert_cpe import _parse_cpe_uri, extract_cpe_triples

SAMPLE_CPE = {
    "products": [
        {
            "cpe": {
                "cpeName": "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*",
                "deprecated": False,
                "titles": [
                    {"title": "Apache HTTP Server 2.4.51", "lang": "en"},
                    {"title": "Serveur HTTP Apache 2.4.51", "lang": "fr"},
                ],
                "created": "2021-10-07",
                "lastModified": "2023-01-15",
            },
        },
        {
            "cpe": {
                "cpeName": "cpe:2.3:o:microsoft:windows_10:21H2:*:*:*:*:*:*:*",
                "deprecated": False,
                "titles": [
                    {"title": "Microsoft Windows 10 21H2", "lang": "en"},
                ],
                "created": "2021-11-01",
            },
        },
        {
            "cpe": {
                "cpeName": "cpe:2.3:h:cisco:catalyst_9300:*:*:*:*:*:*:*:*",
                "deprecated": False,
                "titles": [],
            },
        },
        {
            # Deprecated entry should be skipped
            "cpe": {
                "cpeName": "cpe:2.3:a:oldvendor:oldproduct:1.0:*:*:*:*:*:*:*",
                "deprecated": True,
            },
        },
        {
            # Entry with no cpeName should be skipped
            "cpe": {
                "cpeName": "",
                "deprecated": False,
            },
        },
    ],
}


@pytest.fixture
def sample_json_dir(tmp_path):
    d = tmp_path / "cpe_data"
    d.mkdir()
    (d / "nvdcpe-2.0.json").write_text(json.dumps(SAMPLE_CPE))
    return str(d)


class TestParseCpeUri:
    def test_application(self):
        result = _parse_cpe_uri("cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*")
        assert result["part"] == "application"
        assert result["vendor"] == "apache"
        assert result["product"] == "httpd"
        assert result["version"] == "2.4.51"

    def test_operating_system(self):
        result = _parse_cpe_uri("cpe:2.3:o:microsoft:windows_10:21H2:*:*:*:*:*:*:*")
        assert result["part"] == "operating_system"
        assert result["vendor"] == "microsoft"
        assert result["product"] == "windows_10"
        assert result["version"] == "21H2"

    def test_hardware(self):
        result = _parse_cpe_uri("cpe:2.3:h:cisco:catalyst_9300:*:*:*:*:*:*:*:*")
        assert result["part"] == "hardware"
        assert result["vendor"] == "cisco"
        assert result["product"] == "catalyst_9300"
        assert result["version"] == ""

    def test_wildcard_vendor(self):
        result = _parse_cpe_uri("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
        assert result["vendor"] == ""
        assert result["product"] == ""

    def test_short_uri(self):
        result = _parse_cpe_uri("cpe:2.3")
        assert result == {}


class TestCpeTriples:
    def test_basic_properties(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        ts = set(triples)
        cpe_name = "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*"

        assert (cpe_name, "rdf:type", "Platform") in ts
        assert (cpe_name, "part", "application") in ts
        assert (cpe_name, "vendor", "apache") in ts
        assert (cpe_name, "product", "httpd") in ts
        assert (cpe_name, "version", "2.4.51") in ts

    def test_title_english(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        ts = set(triples)
        cpe_name = "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*"

        assert (cpe_name, "title", "Apache HTTP Server 2.4.51") in ts
        # French title should NOT be included
        assert (cpe_name, "title", "Serveur HTTP Apache 2.4.51") not in ts

    def test_dates(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        ts = set(triples)
        cpe_name = "cpe:2.3:a:apache:httpd:2.4.51:*:*:*:*:*:*:*"

        assert (cpe_name, "created", "2021-10-07") in ts
        assert (cpe_name, "modified", "2023-01-15") in ts

    def test_operating_system_entry(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        ts = set(triples)
        cpe_name = "cpe:2.3:o:microsoft:windows_10:21H2:*:*:*:*:*:*:*"

        assert (cpe_name, "rdf:type", "Platform") in ts
        assert (cpe_name, "part", "operating_system") in ts
        assert (cpe_name, "vendor", "microsoft") in ts

    def test_hardware_entry(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        ts = set(triples)
        cpe_name = "cpe:2.3:h:cisco:catalyst_9300:*:*:*:*:*:*:*:*"

        assert (cpe_name, "rdf:type", "Platform") in ts
        assert (cpe_name, "part", "hardware") in ts

    def test_deprecated_excluded(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        subjects = {s for s, _, _ in triples}

        assert "cpe:2.3:a:oldvendor:oldproduct:1.0:*:*:*:*:*:*:*" not in subjects

    def test_empty_cpe_name_excluded(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        subjects = {s for s, _, _ in triples}

        assert "" not in subjects

    def test_triple_count(self, sample_json_dir):
        triples = list(extract_cpe_triples(sample_json_dir))
        assert len(triples) > 5
        assert len(triples) < 100
