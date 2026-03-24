"""Tests for the STIG profile registry (data/__init__.py registry functions)."""

from __future__ import annotations

import pytest

from stigcode.data import (
    StigProfile,
    get_available_stigs,
    get_default_stig_key,
    get_mapping_database,
    get_stig_profile,
)


class TestLoadRegistry:
    def test_registry_loads_successfully(self):
        profiles = get_available_stigs()
        assert isinstance(profiles, dict)
        assert len(profiles) >= 1

    def test_registry_returns_stig_profile_objects(self):
        profiles = get_available_stigs()
        for profile in profiles.values():
            assert isinstance(profile, StigProfile)


class TestDefaultStig:
    def test_default_stig_is_asd(self):
        assert get_default_stig_key() == "asd"

    def test_default_profile_returns_asd(self):
        profile = get_stig_profile()
        assert profile.key == "asd"


class TestGetStigProfile:
    def test_get_asd_profile(self):
        profile = get_stig_profile("asd")
        assert profile.key == "asd"
        assert profile.name == "Application Security and Development"
        assert profile.version == "V6R3"
        assert profile.mapping_file.name == "asd_stig_v6r3.yaml"
        assert profile.classifications_file.name == "finding_classifications.yaml"
        assert profile.xccdf_file is not None
        assert profile.xccdf_file.name == "application_security_and_development.xml"

    def test_asd_profile_files_exist(self):
        profile = get_stig_profile("asd")
        assert profile.mapping_file.exists(), f"Missing: {profile.mapping_file}"
        assert profile.classifications_file.exists(), f"Missing: {profile.classifications_file}"
        assert profile.xccdf_file is not None and profile.xccdf_file.exists()

    def test_unknown_profile_raises_key_error(self):
        with pytest.raises(KeyError, match="Unknown STIG profile 'nonexistent'"):
            get_stig_profile("nonexistent")

    def test_unknown_profile_lists_available(self):
        with pytest.raises(KeyError, match="asd"):
            get_stig_profile("nonexistent")


class TestGetAvailableStigs:
    def test_returns_at_least_asd(self):
        profiles = get_available_stigs()
        assert "asd" in profiles

    def test_asd_has_description(self):
        profiles = get_available_stigs()
        assert profiles["asd"].description != ""


class TestGetMappingDatabaseWithStigKey:
    def test_stig_key_loads_same_as_filename(self):
        db_by_file = get_mapping_database("asd_stig_v6r3.yaml")
        db_by_key = get_mapping_database(stig_key="asd")
        assert db_by_file.stig_name == db_by_key.stig_name
        assert len(db_by_file.mappings) == len(db_by_key.mappings)

    def test_default_loads_asd(self):
        db = get_mapping_database()
        assert db.stig_name == "Application Security and Development"
