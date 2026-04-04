"""Tests for common.py utility functions."""

import hashlib
import io
import json
import zipfile
from unittest.mock import MagicMock, patch

import requests

from common import (
    _cleanup_old_versions,
    _fingerprint_from_etag,
    _github_commit_sha,
    _github_release_tag,
    _remote_version,
    _ts_from_http_date,
    check_sources_changed,
    download_file,
    download_github_zip,
    get_remote_fingerprint,
    load_metadata,
    save_metadata,
    source_changed,
)


class TestTsFromHttpDate:
    def test_valid_rfc2822(self):
        assert _ts_from_http_date("Wed, 02 Apr 2026 00:54:24 GMT") == "20260402_0054"

    def test_invalid_returns_empty(self):
        assert _ts_from_http_date("not-a-date") == ""

    def test_empty_returns_empty(self):
        assert _ts_from_http_date("") == ""


class TestFingerprintFromEtag:
    def test_simple_etag(self):
        fp = _fingerprint_from_etag('"abc123"')
        assert len(fp) == 12
        assert fp.isalnum()

    def test_weak_etag_stripped(self):
        """W/ prefix must be stripped as a substring, not character-by-character."""
        fp_strong = _fingerprint_from_etag('"abc123"')
        fp_weak = _fingerprint_from_etag('W/"abc123"')
        assert fp_strong == fp_weak

    def test_empty_returns_empty(self):
        assert _fingerprint_from_etag("") == ""
        assert _fingerprint_from_etag('""') == ""

    def test_weak_prefix_with_tricky_content(self):
        """Ensure W/ is stripped as prefix, not lstrip-style char removal."""
        fp = _fingerprint_from_etag('W/"Weakling"')
        # The content should be "Weakling" (W not stripped from content)
        expected = hashlib.sha256(b"Weakling").hexdigest()[:12]
        assert fp == expected


class TestRemoteVersion:
    @patch("common.requests.head")
    def test_last_modified_preferred(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.headers = {
            "Last-Modified": "Thu, 03 Apr 2026 13:31:16 GMT",
            "ETag": '"some-etag"',
        }
        mock_head.return_value = mock_resp
        assert _remote_version("http://example.com/file") == "20260403_1331"

    @patch("common.requests.head")
    def test_etag_fallback(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.headers = {"Last-Modified": "", "ETag": '"abc123"'}
        mock_head.return_value = mock_resp
        result = _remote_version("http://example.com/file")
        assert len(result) == 12

    @patch("common.requests.head")
    def test_no_headers_returns_empty(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_head.return_value = mock_resp
        assert _remote_version("http://example.com/file") == ""

    @patch("common.requests.head", side_effect=requests.RequestException("timeout"))
    def test_exception_returns_empty(self, mock_head):
        assert _remote_version("http://example.com/file") == ""


class TestCleanupOldVersions:
    def test_removes_old_keeps_current(self, tmp_path):
        old1 = tmp_path / "data_v1.json"
        old2 = tmp_path / "data_v2.json"
        current = tmp_path / "data_v3.json"
        for f in (old1, old2, current):
            f.write_text("{}")

        _cleanup_old_versions(tmp_path, "data", ".json", current)

        assert not old1.exists()
        assert not old2.exists()
        assert current.exists()

    def test_no_old_versions(self, tmp_path):
        current = tmp_path / "data_v1.json"
        current.write_text("{}")
        _cleanup_old_versions(tmp_path, "data", ".json", current)
        assert current.exists()


class TestDownloadFile:
    @patch("common._remote_version", return_value="20260403_120000")
    @patch("common.requests.get")
    def test_version_override_takes_priority(self, mock_get, mock_rv, tmp_path):
        mock_resp = MagicMock()
        mock_resp.iter_content = MagicMock(return_value=[b"hello"])
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        path = download_file(
            "http://example.com/data.json",
            "data.json",
            str(tmp_path),
            version_override="mysha123",
        )
        assert "mysha123" in path.name
        # _remote_version should NOT have been called
        mock_rv.assert_not_called()

    @patch("common._remote_version", return_value="20260403_120000")
    @patch("common.requests.get")
    def test_cached_file_not_redownloaded(self, mock_get, mock_rv, tmp_path):
        # Pre-create the versioned file
        cached = tmp_path / "data_20260403_120000.json"
        cached.write_text("{}")

        path = download_file("http://example.com/data.json", "data.json", str(tmp_path))
        assert path == cached
        mock_get.assert_not_called()

    @patch("common._remote_version", return_value="v2")
    @patch("common.requests.get")
    def test_old_versions_cleaned_up(self, mock_get, mock_rv, tmp_path):
        # Pre-create old versions
        old = tmp_path / "data_v1.json"
        old.write_text("{}")

        mock_resp = MagicMock()
        mock_resp.iter_content = MagicMock(return_value=[b"new data"])
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        path = download_file("http://example.com/data.json", "data.json", str(tmp_path))
        assert "v2" in path.name
        assert not old.exists()


class TestDownloadGithubZip:
    @patch("common._github_commit_sha", return_value="abcdef123456")
    @patch("common.requests.get")
    def test_uses_commit_sha_as_version(self, mock_get, mock_sha, tmp_path):
        # Create a valid ZIP in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("test.txt", "hello")
        zip_bytes = buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.iter_content = MagicMock(return_value=[zip_bytes])
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = download_github_zip("owner", "repo", "test.zip", "main", str(tmp_path))
        mock_sha.assert_called_once_with("owner", "repo", "main")
        # The ZIP should be named with the SHA
        assert any("abcdef123456" in f.name for f in tmp_path.iterdir())
        assert result.is_dir()

    @patch("common._github_commit_sha", side_effect=requests.RequestException("API error"))
    @patch("common._remote_version", return_value="fallback_ver")
    @patch("common.requests.get")
    def test_falls_back_on_sha_failure(self, mock_get, mock_rv, mock_sha, tmp_path):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("test.txt", "hello")
        zip_bytes = buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.iter_content = MagicMock(return_value=[zip_bytes])
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = download_github_zip("owner", "repo", "test.zip", "main", str(tmp_path))
        assert result.is_dir()


class TestGithubHelpers:
    @patch("common.requests.get")
    def test_github_commit_sha(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"sha": "a" * 40}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        assert _github_commit_sha("owner", "repo", "main") == "a" * 12

    @patch("common.requests.get")
    def test_github_release_tag(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"tag_name": "v1.2.3"}
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp
        assert _github_release_tag("owner", "repo") == "v1.2.3"


class TestGetRemoteFingerprint:
    @patch("common._github_commit_sha", return_value="abcdef123456")
    def test_github_sha_method(self, mock_sha):
        fp = get_remote_fingerprint("attack")
        assert fp == "sha:abcdef123456"
        mock_sha.assert_called_once_with("mitre-attack", "attack-stix-data", "master")

    @patch("common._github_release_tag", return_value="v2026.04.03")
    def test_github_release_method(self, mock_tag):
        fp = get_remote_fingerprint("cve")
        assert fp == "tag:v2026.04.03"

    @patch("common.requests.head")
    def test_http_last_modified_method(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.headers = {"Last-Modified": "Thu, 03 Apr 2026 13:31:16 GMT", "ETag": ""}
        mock_head.return_value = mock_resp
        fp = get_remote_fingerprint("capec")
        assert fp.startswith("lm:")

    @patch("common.requests.head")
    def test_http_etag_method(self, mock_head):
        mock_resp = MagicMock()
        mock_resp.headers = {"Last-Modified": "", "ETag": '"some-etag"'}
        mock_head.return_value = mock_resp
        fp = get_remote_fingerprint("capec")
        assert fp.startswith("etag:")

    def test_unknown_source_returns_empty(self):
        assert get_remote_fingerprint("nonexistent") == ""


class TestCheckSourcesChanged:
    @patch("common.get_remote_fingerprint")
    def test_detects_changed_source(self, mock_fp):
        mock_fp.return_value = "sha:new_value"
        previous = {"attack": "sha:old_value", "capec": "sha:new_value"}
        changed = check_sources_changed(previous)
        assert changed["attack"] is True

    @patch("common.get_remote_fingerprint")
    def test_detects_unchanged_source(self, mock_fp):
        mock_fp.return_value = "sha:same_value"
        previous = {"attack": "sha:same_value"}
        changed = check_sources_changed(previous)
        assert changed["attack"] is False

    @patch("common.get_remote_fingerprint", return_value="")
    def test_failed_fingerprint_marks_changed(self, mock_fp):
        previous = {"attack": "sha:some_value"}
        changed = check_sources_changed(previous)
        assert changed["attack"] is True


class TestMetadata:
    def test_save_and_load(self, tmp_path, monkeypatch):
        meta_file = tmp_path / "hf_dataset" / ".metadata.json"
        monkeypatch.setattr("common.METADATA_FILE", meta_file)

        save_metadata({"key": "value"})
        assert meta_file.exists()
        loaded = load_metadata()
        assert loaded["key"] == "value"

    def test_load_missing_returns_empty(self, tmp_path, monkeypatch):
        meta_file = tmp_path / "hf_dataset" / ".metadata.json"
        monkeypatch.setattr("common.METADATA_FILE", meta_file)
        assert load_metadata() == {}


class TestSourceChanged:
    def test_missing_parquet_means_changed(self, tmp_path, monkeypatch):
        monkeypatch.setattr("common.METADATA_FILE", tmp_path / ".metadata.json")
        assert source_changed(tmp_path, "test", "/path/to/file_v1.json") is True

    def test_matching_fingerprint_means_unchanged(self, tmp_path, monkeypatch):
        meta_file = tmp_path / ".metadata.json"
        meta_file.write_text(json.dumps({"converter_fingerprints": {"test": "file_v1.json"}}))
        monkeypatch.setattr("common.METADATA_FILE", meta_file)

        (tmp_path / "test.parquet").write_bytes(b"fake")
        assert source_changed(tmp_path, "test", "/path/to/file_v1.json") is False

    def test_different_fingerprint_means_changed(self, tmp_path, monkeypatch):
        meta_file = tmp_path / ".metadata.json"
        meta_file.write_text(json.dumps({"converter_fingerprints": {"test": "file_v1.json"}}))
        monkeypatch.setattr("common.METADATA_FILE", meta_file)

        (tmp_path / "test.parquet").write_bytes(b"fake")
        assert source_changed(tmp_path, "test", "/path/to/file_v2.json") is True
