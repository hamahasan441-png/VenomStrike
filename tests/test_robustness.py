"""Tests for robustness improvements — retry logic, config validation, engine features."""
import os
import sys
import tempfile
import time
import importlib
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Config validation tests ────────────────────────────────────────


class TestConfigValidation:
    """Verify that config values are clamped to safe bounds."""

    def test_int_env_valid(self):
        from config import _int_env
        assert _int_env("NONEXISTENT_KEY", 42) == 42

    def test_int_env_bounds(self):
        from config import _int_env
        with patch.dict(os.environ, {"TEST_VAL": "-5"}):
            assert _int_env("TEST_VAL", 10, lo=1) == 1
        with patch.dict(os.environ, {"TEST_VAL": "999"}):
            assert _int_env("TEST_VAL", 10, hi=100) == 100

    def test_int_env_invalid_string(self):
        from config import _int_env
        with patch.dict(os.environ, {"TEST_VAL": "not_a_number"}):
            assert _int_env("TEST_VAL", 10) == 10

    def test_float_env_valid(self):
        from config import _float_env
        assert _float_env("NONEXISTENT_KEY", 3.14) == 3.14

    def test_float_env_bounds(self):
        from config import _float_env
        with patch.dict(os.environ, {"TEST_VAL": "-1.0"}):
            assert _float_env("TEST_VAL", 0.5, lo=0.0) == 0.0
        with patch.dict(os.environ, {"TEST_VAL": "999.9"}):
            assert _float_env("TEST_VAL", 0.5, hi=60.0) == 60.0

    def test_float_env_invalid_string(self):
        from config import _float_env
        with patch.dict(os.environ, {"TEST_VAL": "bad"}):
            assert _float_env("TEST_VAL", 1.5) == 1.5

    def test_new_config_keys_exist(self):
        import config
        assert hasattr(config, "RETRY_ATTEMPTS")
        assert hasattr(config, "RETRY_BACKOFF")
        assert hasattr(config, "VERIFY_SSL")
        assert hasattr(config, "MODULE_TIMEOUT")
        assert hasattr(config, "TIMING_TOLERANCE")

    def test_validation_attempts_configurable(self):
        import config
        assert config.VALIDATION_ATTEMPTS >= 1
        assert config.VALIDATION_ATTEMPTS <= 10


# ── Retry logic tests ──────────────────────────────────────────────


class TestRetryLogic:
    """Verify the make_request retry behaviour."""

    def test_make_request_no_retry_on_success(self):
        """Successful requests should not be retried."""
        import requests
        from core.utils import make_request

        session = MagicMock(spec=requests.Session)
        mock_resp = MagicMock(spec=requests.Response)
        session.request.return_value = mock_resp

        result = make_request(session, "GET", "http://example.com", retries=3)
        assert result is mock_resp
        assert session.request.call_count == 1

    def test_make_request_retries_on_connection_error(self):
        """Connection errors should trigger retries."""
        import requests
        from core.utils import make_request

        session = MagicMock(spec=requests.Session)
        mock_resp = MagicMock(spec=requests.Response)
        session.request.side_effect = [
            requests.exceptions.ConnectionError("reset"),
            mock_resp,
        ]

        result = make_request(
            session, "GET", "http://example.com", retries=2, backoff=0.01
        )
        assert result is mock_resp
        assert session.request.call_count == 2

    def test_make_request_retries_on_timeout(self):
        """Timeout errors should trigger retries."""
        import requests
        from core.utils import make_request

        session = MagicMock(spec=requests.Session)
        session.request.side_effect = requests.exceptions.Timeout("timed out")

        result = make_request(
            session, "GET", "http://example.com", retries=2, backoff=0.01
        )
        assert result is None
        assert session.request.call_count == 3  # 1 initial + 2 retries

    def test_make_request_zero_retries(self):
        """With retries=0, only one attempt should be made."""
        import requests
        from core.utils import make_request

        session = MagicMock(spec=requests.Session)
        session.request.side_effect = requests.exceptions.ConnectionError("fail")

        result = make_request(
            session, "GET", "http://example.com", retries=0, backoff=0.01
        )
        assert result is None
        assert session.request.call_count == 1

    def test_make_request_passes_verify_flag(self):
        """The verify parameter should be forwarded to session.request."""
        import requests
        from core.utils import make_request

        session = MagicMock(spec=requests.Session)
        mock_resp = MagicMock(spec=requests.Response)
        session.request.return_value = mock_resp

        make_request(session, "GET", "http://example.com", verify=True, retries=0)
        call_kwargs = session.request.call_args[1]
        assert call_kwargs["verify"] is True


# ── Engine features tests ──────────────────────────────────────────


class TestEngineCancellation:
    """Verify the engine's graceful cancellation flag."""

    def test_engine_cancel_flag(self):
        from core.engine import ScanEngine
        engine = ScanEngine(enable_integrations=False)
        assert engine._cancelled is False
        engine.cancel()
        assert engine._cancelled is True


# ── Database index tests ───────────────────────────────────────────


class TestDatabaseIndices:
    """Verify that database indices are created."""

    def test_indices_created(self):
        import sqlite3
        from config import DB_PATH
        from core.database import init_db

        # Use a cross-platform temp database
        fd, test_db = tempfile.mkstemp(suffix=".db", prefix="test_venomstrike_idx_")
        os.close(fd)
        try:
            with patch("core.database.DB_PATH", test_db):
                with patch("config.DB_PATH", test_db):
                    original_get = __import__("core.database", fromlist=["get_connection"]).get_connection

                    def patched_get():
                        conn = sqlite3.connect(test_db)
                        conn.row_factory = sqlite3.Row
                        return conn

                    with patch("core.database.get_connection", patched_get):
                        init_db()
                        conn = sqlite3.connect(test_db)
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='findings'"
                        )
                        index_names = {row[0] for row in cursor.fetchall()}
                        conn.close()

            assert "idx_findings_scan_id" in index_names
            assert "idx_findings_severity" in index_names
            assert "idx_findings_confidence" in index_names
        finally:
            if os.path.exists(test_db):
                os.remove(test_db)


# ── Validator improvement tests ────────────────────────────────────


class TestValidatorImprovements:
    """Verify validator uses configurable timing tolerance."""

    def test_timing_tolerance_from_config(self):
        """is_timing_anomaly should use TIMING_TOLERANCE from config by default."""
        import requests
        from core.validator import ResultValidator

        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)

        # Pre-set a cached baseline so calibrate_timing isn't called
        validator._timing_baselines["http://example.com"] = 0.2

        # With default tolerance of 1.5s and sleep of 5s:
        # threshold = max(0.2 + 5.0 - 1.5, 5.0 * 0.7) = max(3.7, 3.5) = 3.7
        assert validator.is_timing_anomaly("http://example.com", 4.0) is True
        assert validator.is_timing_anomaly("http://example.com", 3.0) is False

    def test_timing_tolerance_override(self):
        """Explicit tolerance parameter should override the config default."""
        import requests
        from core.validator import ResultValidator

        session = MagicMock(spec=requests.Session)
        validator = ResultValidator(session)
        validator._timing_baselines["http://example.com"] = 0.2

        # With tolerance=0.5: threshold = max(0.2 + 5.0 - 0.5, 3.5) = max(4.7, 3.5) = 4.7
        assert validator.is_timing_anomaly("http://example.com", 5.0, tolerance=0.5) is True
        assert validator.is_timing_anomaly("http://example.com", 4.0, tolerance=0.5) is False
