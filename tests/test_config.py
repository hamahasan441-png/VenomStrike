"""Tests for VenomStrike configuration."""
import os
import sys

# Ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_config_imports():
    """Config module should import without error."""
    import config
    assert hasattr(config, "VERSION")
    assert hasattr(config, "TOOL_NAME")


def test_version_format():
    """Version should be semver format."""
    import config
    parts = config.VERSION.split(".")
    assert len(parts) == 3
    for part in parts:
        assert part.isdigit()


def test_severity_levels():
    """All severity levels and colors should be defined."""
    import config
    levels = ["Critical", "High", "Medium", "Low", "Info"]
    for level in levels:
        assert level in config.SEVERITY_COLORS
        assert config.SEVERITY_COLORS[level].startswith("#")


def test_default_values():
    """Default config values should be reasonable."""
    import config
    assert 1 <= config.DEFAULT_TIMEOUT <= 60
    assert 1 <= config.DEFAULT_THREADS <= config.MAX_THREADS
    assert config.MIN_CONFIDENCE >= 0
    assert config.MIN_CONFIDENCE <= 100
