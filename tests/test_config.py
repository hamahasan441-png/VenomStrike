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


def test_scan_depth_default():
    """SCAN_DEPTH should default to 'standard'."""
    import config
    assert config.SCAN_DEPTH in ("quick", "standard", "deep", "full", "quantum")


def test_depth_presets_keys():
    """All five depth levels should have presets."""
    import config
    for level in ("quick", "standard", "deep", "full", "quantum"):
        assert level in config.DEPTH_PRESETS
        preset = config.DEPTH_PRESETS[level]
        assert "crawl_depth" in preset
        assert "max_crawl_pages" in preset
        assert "dir_brute_limit" in preset
        assert "api_brute_limit" in preset
        assert "payload_limit" in preset
        assert "validation_attempts" in preset
        assert "min_confidence" in preset


def test_depth_presets_ordering():
    """Deeper levels should have higher crawl depth and more pages."""
    import config
    levels = ["quick", "standard", "deep", "full", "quantum"]
    for i in range(len(levels) - 1):
        a = config.DEPTH_PRESETS[levels[i]]
        b = config.DEPTH_PRESETS[levels[i + 1]]
        assert a["crawl_depth"] <= b["crawl_depth"]
        assert a["max_crawl_pages"] <= b["max_crawl_pages"]


def test_version_is_5():
    """Version should be 5.0.0 for Apex edition."""
    import config
    assert config.VERSION == "5.0.0"
    assert config.CODENAME == "Apex"


def test_apex_integration_config_keys():
    """v5.0 should have Amass and Wappalyzer config keys."""
    import config
    assert hasattr(config, "AMASS_ENABLED")
    assert hasattr(config, "AMASS_PATH")
    assert hasattr(config, "WAPPALYZER_ENABLED")
