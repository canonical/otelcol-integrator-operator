#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit tests for otelcol_integrator library."""

import json
from unittest.mock import MagicMock

import pytest
from ops import SecretNotFoundError
from pydantic import ValidationError

from charms.otelcol_integrator.v0.otelcol_integrator import (
    OtelcolIntegratorProviderRelationUpdater,
    OtelcolIntegratorProviderAppData,
    OtelcolIntegratorRequirer,
    SecretURI,
)


# Fixtures


@pytest.fixture
def simple_config():
    """Fixture for simple YAML config without secrets."""
    return """
exporters:
  splunk_hec:
    token: "QWERTY"
    endpoint: "https://splunk:8088/services/collector"
    max_idle_conns: 20
    """

@pytest.fixture
def config_with_inline_secret():
    """Fixture for config with inline secret reference."""
    return """
exporters:
  splunk_hec:
    token: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/token?render=inline"
    endpoint: "https://splunk:8088/services/collector"
    max_idle_conns: 20
"""


@pytest.fixture
def config_with_file_secret():
    """Fixture for config with file-based secret reference."""
    return """
exporters:
  splunk_hec:
    token: "QWERTY"
    endpoint: "https://splunk:8088/services/collector"
    max_idle_conns: 20
    timeout: 100s
    tls:
      insecure_skip_verify: true
      key_file: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/keyfile?render=file"
"""


@pytest.fixture
def config_with_multiple_secrets():
    """Fixture for config with multiple secret references."""
    return """
exporters:
  splunk_hec:
    token: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/token?render=inline"
    endpoint: "https://splunk:8088/services/collector"
    max_idle_conns: 20
    timeout: 100s
    tls:
      insecure_skip_verify: true
      ca_file: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/cafile?render=file"
      cert_file: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/certfile?render=file"
      key_file: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/keyfile?render=file"
"""


# Tests for SecretURI


@pytest.mark.parametrize(
    "uri,expected_model_uuid,expected_secret_id,expected_key,expected_render",
    [
        (
            "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/token?render=inline",
            "ac2bcddf-4c37-42d4-8ac6-5e7f922c2437",
            "d5o1h2vmp25c762tsbug",
            "token",
            "inline",
        ),
        (
            "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/cafile?render=file",
            "ac2bcddf-4c37-42d4-8ac6-5e7f922c2437",
            "d5o1h2vmp25c762tsbug",
            "cafile",
            "file",
        ),
    ],
    ids=["inline_render", "file_render"],
)
def test_secret_uri_from_valid_uri(
    uri, expected_model_uuid, expected_secret_id, expected_key, expected_render
):
    """Test parsing valid secret URIs with different render modes."""
    # GIVEN: A valid secret URI
    # WHEN: Parsing the URI
    secret = SecretURI.from_uri(uri)

    # THEN: All fields are correctly extracted
    assert secret.model_uuid == expected_model_uuid
    assert secret.secret_id == expected_secret_id
    assert secret.key == expected_key
    assert secret.render == expected_render


def test_secret_uri_to_uri():
    """Test converting a SecretURI back to URI string."""
    # GIVEN: A SecretURI instance
    secret = SecretURI(
        model_uuid="ac2bcddf-4c37-42d4-8ac6-5e7f922c2437",
        secret_id="d5o1h2vmp25c762tsbug",
        key="token",
        render="inline",
    )

    # WHEN: Converting to URI string
    uri = secret.to_uri()

    # THEN: The URI is correctly formatted
    assert uri == "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/token?render=inline"

@pytest.mark.parametrize(
    "uri",
    [
        ("secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/token?render=inline"),
        ("secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/kefile?render=file")
    ]
)
def test_secret_uri_roundtrip(uri):
    """Test parsing and converting back to URI produces the same result."""
    # GIVEN: A valid secret URI
    # WHEN: Parsing and converting back
    secret = SecretURI.from_uri(uri)
    result_uri = secret.to_uri()

    # THEN: The URI is unchanged
    assert result_uri == uri


@pytest.mark.parametrize(
    "uri,error_match",
    [
        (
            "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug?render=inline",
            "Secret URI must include a key",
        ),
        (
            "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/token",
            "Secret URI must include render query parameter",
        ),
        (
            "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5o1h2vmp25c762tsbug/token?render=invalid",
            "render parameter must be 'inline' or 'file'",
        ),
    ],
    ids=["missing_key", "missing_render", "invalid_render_value"],
)
def test_secret_uri_invalid_formats(uri, error_match):
    """Test that invalid secret URI formats raise appropriate errors."""
    # GIVEN: An invalid secret URI
    # WHEN/THEN: Parsing raises ValueError with appropriate message
    with pytest.raises(ValueError, match=error_match):
        SecretURI.from_uri(uri)


def test_secret_uri_malformed_uri():
    """Test that malformed URI raises error."""
    # GIVEN: A malformed secret URI
    uri = "not-a-secret-uri"

    # WHEN/THEN: Parsing raises ValueError (could be various messages)
    with pytest.raises(ValueError):
        SecretURI.from_uri(uri)


# Tests for OtelcolIntegratorProviderAppData

def test_valid_data_without_secrets(simple_config):
    """Test creating valid relation data without secrets."""
    # GIVEN: A simple YAML config and valid pipelines
    # WHEN: Creating OtelcolIntegratorProviderAppData
    data = OtelcolIntegratorProviderAppData(
        config_yaml=simple_config,
        pipelines=["metrics", "traces"],
    )

    # THEN: Data is stored correctly
    assert data.config_yaml == simple_config
    assert data.pipelines == ["metrics", "traces"]


@pytest.mark.parametrize("pipelines", [
    ["metrics"],
    ["logs"],
    ["traces"],
    ["metrics", "logs"],
    ["metrics", "traces"],
    ["logs", "traces"],
    ["metrics", "logs", "traces"],
])
def test_valid_pipelines(simple_config, pipelines):
    """Test creating valid relation data with different pipeline combinations."""
    # GIVEN: A simple config and valid pipeline combination
    # WHEN: Creating OtelcolIntegratorProviderAppData
    data = OtelcolIntegratorProviderAppData(
        config_yaml=simple_config,
        pipelines=pipelines,
    )

    # THEN: Pipelines are stored correctly
    assert data.pipelines == pipelines


@pytest.mark.parametrize("invalid_pipelines,error_match", [
    ([], "At least one pipeline must be enabled"),
    (["metrics", "invalid_pipeline"], "Invalid pipelines"),
    (["invalid"], "Invalid pipelines"),
    (["metrics", "logs", "invalid"], "Invalid pipelines"),
])
def test_invalid_pipelines(simple_config, invalid_pipelines, error_match):
    """Test that invalid pipeline combinations raise ValidationError."""
    # GIVEN: Invalid pipeline combinations
    # WHEN: Creating OtelcolIntegratorProviderAppData
    # THEN: ValidationError is raised with appropriate message
    with pytest.raises(ValidationError, match=error_match):
        OtelcolIntegratorProviderAppData(
            config_yaml=simple_config,
            pipelines=invalid_pipelines,
        )


@pytest.mark.parametrize("config_fixture,expected_marker", [
    ("config_with_inline_secret", "render=inline"),
    ("config_with_file_secret", "render=file"),
    ("config_with_multiple_secrets", "render=inline"),
    ("config_with_multiple_secrets", "render=file"),
])
def test_valid_data_with_secrets(config_fixture, expected_marker, request):
    """Test creating valid relation data with different secret types."""
    # GIVEN: A config with secrets and expected render type
    config = request.getfixturevalue(config_fixture)

    # WHEN: Creating OtelcolIntegratorProviderAppData
    data = OtelcolIntegratorProviderAppData(
        config_yaml=config,
        pipelines=["metrics"],
    )

    # THEN: Secrets are preserved and render type is correct
    assert "secret://" in data.config_yaml
    assert expected_marker in data.config_yaml


@pytest.mark.parametrize("invalid_config,error_match", [
    ("", "config_yaml cannot be empty"),
    ("   \n  \t  ", "config_yaml cannot be empty"),
    ("invalid: [unclosed", "Invalid YAML"),
])
def test_invalid_config_yaml_raises_error(invalid_config, error_match):
    """Test that invalid config_yaml raises ValidationError."""
    # GIVEN: Invalid YAML config (empty, whitespace, or malformed)
    # WHEN: Creating OtelcolIntegratorProviderAppData
    # THEN: ValidationError is raised with appropriate message
    with pytest.raises(ValidationError, match=error_match):
        OtelcolIntegratorProviderAppData(
            config_yaml=invalid_config,
            pipelines=["metrics"],
        )


@pytest.mark.parametrize("secret_uri,error_match", [
    ("auth: secret://8cec38a1-1c16-4d0e-8174-46aa32ee692d/d5ltigvmp25c762tsbr0?render=inline",
     "Secret URI must include a key"),
    ("auth: secret://8cec38a1-1c16-4d0e-8174-46aa32ee692d/d5ltigvmp25c762tsbr0/token",
     "Secret URI must include render query parameter"),
    ("auth: secret://8cec38a1-1c16-4d0e-8174-46aa32ee692d/d5ltigvmp25c762tsbr0/token?render=invalid",
     "render parameter must be 'inline' or 'file'"),
])
def test_invalid_secret_uri_raises_error(secret_uri, error_match):
    """Test that invalid secret URIs raise ValidationError."""
    # GIVEN: Config with invalid secret URI format
    # WHEN: Creating OtelcolIntegratorProviderAppData
    # THEN: ValidationError is raised with appropriate message
    with pytest.raises(ValidationError, match=error_match):
        OtelcolIntegratorProviderAppData(
            config_yaml=secret_uri,
            pipelines=["metrics"],
        )

def test_multiple_secrets_valid(config_with_multiple_secrets):
    """Test config with multiple valid secret references."""
    # GIVEN: A config with multiple secret references
    # WHEN: Creating OtelcolIntegratorProviderAppData
    data = OtelcolIntegratorProviderAppData(
        config_yaml=config_with_multiple_secrets,
        pipelines=["metrics", "logs"],
    )
    # THEN: All secrets are preserved in config
    assert data.config_yaml == config_with_multiple_secrets


# Tests for OtelcolIntegratorProviderRelationUpdater

def test_update_relations_data_with_single_relation(simple_config):
    """Test updating a single relation with config data."""
    # GIVEN: An application with one relation
    app = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.data = {app: {}}

    data = OtelcolIntegratorProviderAppData(
        config_yaml=simple_config,
        pipelines=["metrics", "logs"],
    )

    # WHEN: Updating relation data
    OtelcolIntegratorProviderRelationUpdater.update_relations_data(
        application=app,
        relations=[relation],
        data=data,
    )

    # THEN: Relation data is updated correctly
    assert relation.data[app]["config_yaml"] == simple_config
    assert relation.data[app]["pipelines"] == json.dumps(["metrics", "logs"])


def test_update_relations_data_with_multiple_relations(simple_config):
    """Test updating multiple relations with same config data."""
    # GIVEN: An application with multiple relations
    app = MagicMock()
    relation1 = MagicMock()
    relation1.id = 1
    relation1.data = {app: {}}
    relation2 = MagicMock()
    relation2.id = 2
    relation2.data = {app: {}}

    data = OtelcolIntegratorProviderAppData(
        config_yaml=simple_config,
        pipelines=["traces"],
    )

    # WHEN: Updating relation data
    OtelcolIntegratorProviderRelationUpdater.update_relations_data(
        application=app,
        relations=[relation1, relation2],
        data=data,
    )

    # THEN: All relations are updated with same config
    assert relation1.data[app]["config_yaml"] == simple_config
    assert relation1.data[app]["pipelines"] == json.dumps(["traces"])
    assert relation2.data[app]["config_yaml"] == simple_config
    assert relation2.data[app]["pipelines"] == json.dumps(["traces"])


def test_update_relations_data_with_empty_relations_list(simple_config):
    """Test that empty relations list does nothing."""
    # GIVEN: Valid data but empty relations list
    app = MagicMock()
    data = OtelcolIntegratorProviderAppData(
        config_yaml=simple_config,
        pipelines=["metrics"],
    )

    # WHEN: Updating with empty relations list
    OtelcolIntegratorProviderRelationUpdater.update_relations_data(
        application=app,
        relations=[],
        data=data,
    )

    # THEN: No operations performed (early return)
    assert not app.method_calls


def test_update_relations_data_with_secrets(config_with_inline_secret):
    """Test updating relation with config containing secrets."""
    # GIVEN: Config with secret URIs
    app = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.data = {app: {}}

    data = OtelcolIntegratorProviderAppData(
        config_yaml=config_with_inline_secret,
        pipelines=["metrics"],
    )

    # WHEN: Updating relation data
    OtelcolIntegratorProviderRelationUpdater.update_relations_data(
        application=app,
        relations=[relation],
        data=data,
    )

    # THEN: Secrets are preserved in relation data
    assert relation.data[app]["config_yaml"] == config_with_inline_secret
    assert "secret://" in relation.data[app]["config_yaml"]
    assert relation.data[app]["pipelines"] == json.dumps(["metrics"])


def test_update_relations_data_overwrites_existing_data(simple_config):
    """Test that updating relation overwrites existing data."""
    # GIVEN: Relation with existing old data
    app = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.data = {app: {"config_yaml": "old_config", "pipelines": '["logs"]'}}

    data = OtelcolIntegratorProviderAppData(
        config_yaml=simple_config,
        pipelines=["metrics", "traces"],
    )

    # WHEN: Updating relation data
    OtelcolIntegratorProviderRelationUpdater.update_relations_data(
        application=app,
        relations=[relation],
        data=data,
    )

    # THEN: Old data is completely replaced
    assert relation.data[app]["config_yaml"] == simple_config
    assert relation.data[app]["config_yaml"] != "old_config"
    assert relation.data[app]["pipelines"] == json.dumps(["metrics", "traces"])


# Tests for OtelcolIntegratorRequirer


def test_retrieve_external_configs_no_relations():
    """Test retrieving configs when no relations exist."""
    # GIVEN: A model with no relations
    model = MagicMock()
    model.relations.get.return_value = []

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: Empty list is returned
    assert configs == []


def test_retrieve_external_configs_skips_relation_without_app_data():
    """Test that relations without app data are skipped."""
    # GIVEN: A model with one relation that has NO app data
    model = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.app = MagicMock()
    relation.data = {}  # No data for relation.app

    model.relations.get.return_value = [relation]

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: Empty list is returned (relation was skipped)
    assert configs == []


def test_retrieve_external_configs_with_valid_data(simple_config):
    """Test retrieving configs with valid relation data."""
    # GIVEN: A model with one relation containing valid data
    model = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.app = MagicMock()
    relation.data = {
        relation.app: {
            "config_yaml": simple_config,
            "pipelines": json.dumps(["metrics", "logs"])
        }
    }
    model.relations.get.return_value = [relation]

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: Valid config is returned
    assert len(configs) == 1
    assert configs[0]["config_yaml"] == simple_config
    assert configs[0]["pipelines"] == ["metrics", "logs"]


@pytest.mark.parametrize("config_yaml,pipelines_data,description", [
    ("exporters:\n  splunk:", "invalid json[", "invalid JSON in pipelines"),
    ("", json.dumps(["metrics"]), "empty config_yaml"),
    ("exporters:\n  splunk:", json.dumps(["invalid_pipeline"]), "invalid pipeline name"),
    ("   \n  \t  ", json.dumps(["logs"]), "whitespace-only config_yaml"),
])
def test_retrieve_external_configs_skips_invalid_data(config_yaml, pipelines_data, description):
    """Test that configs with invalid data are skipped with warning."""
    # GIVEN: A relation with invalid data (varied scenarios)
    model = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.app = MagicMock()
    relation.data = {
        relation.app: {
            "config_yaml": config_yaml,
            "pipelines": pipelines_data
        }
    }
    model.relations.get.return_value = [relation]

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: No configs are returned (invalid data skipped)
    assert configs == []


def test_retrieve_external_configs_with_multiple_relations(simple_config):
    """Test retrieving configs from multiple relations."""
    # GIVEN: A model with two relations containing valid data
    model = MagicMock()

    relation1 = MagicMock()
    relation1.id = 1
    relation1.app = MagicMock()
    relation1.data = {
        relation1.app: {
            "config_yaml": simple_config,
            "pipelines": json.dumps(["metrics"])
        }
    }

    relation2 = MagicMock()
    relation2.id = 2
    relation2.app = MagicMock()
    relation2.data = {
        relation2.app: {
            "config_yaml": "receivers:\n  prometheus:",
            "pipelines": json.dumps(["logs"])
        }
    }

    model.relations.get.return_value = [relation1, relation2]

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: Both configs are returned
    assert len(configs) == 2
    assert configs[0]["pipelines"] == ["metrics"]
    assert configs[1]["pipelines"] == ["logs"]


def test_retrieve_external_configs_resolves_inline_secrets(config_with_inline_secret):
    """Test that inline secrets are resolved in config."""
    # GIVEN: A relation with config containing inline secrets
    model = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.app = MagicMock()

    relation.data = {
        relation.app: {
            "config_yaml": config_with_inline_secret,
            "pipelines": json.dumps(["metrics"])
        }
    }
    model.relations.get.return_value = [relation]

    # Mock secret retrieval
    mock_secret = MagicMock()
    mock_secret.get_content.return_value = {"token": "secret-value-123"}
    model.get_secret.return_value = mock_secret

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: Secret URI is replaced with actual value
    assert len(configs) == 1
    assert "secret://" not in configs[0]["config_yaml"]
    assert "secret-value-123" in configs[0]["config_yaml"]


def test_retrieve_external_configs_tracks_file_secrets(config_with_file_secret):
    """Test that file-based secrets are tracked in secret_files."""
    # GIVEN: A relation with config containing file-based secrets
    model = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.app = MagicMock()

    relation.data = {
        relation.app: {
            "config_yaml": config_with_file_secret,
            "pipelines": json.dumps(["metrics"])
        }
    }
    model.relations.get.return_value = [relation]

    # Mock secret retrieval
    mock_secret = MagicMock()
    mock_secret.get_content.return_value = {"keyfile": "certificate-content"}
    model.get_secret.return_value = mock_secret

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: File path is in config and secret_files mapping exists
    assert len(configs) == 1
    assert "/tmp/secrets" in configs[0]["config_yaml"]
    assert "d5o1h2vmp25c762tsbug_keyfile" in configs[0]["config_yaml"]
    assert len(requirer.secret_files) == 1
    assert "certificate-content" in requirer.secret_files.values()

    assert "certificate-content" in requirer.secret_files.values()


def test_retrieve_external_configs_handles_secret_not_found(config_with_inline_secret):
    """Test that SecretNotFoundError is handled gracefully."""
    # GIVEN: A relation with secrets that don't exist in Juju
    model = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.app = MagicMock()

    relation.data = {
        relation.app: {
            "config_yaml": config_with_inline_secret,
            "pipelines": json.dumps(["metrics"])
        }
    }
    model.relations.get.return_value = [relation]

    # Mock secret not found
    model.get_secret.side_effect = SecretNotFoundError("secret-id")

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: Relation is skipped due to secret resolution failure
    assert len(configs) == 0


def test_retrieve_external_configs_handles_secret_fetch_error(config_with_inline_secret):
    """Test that generic exceptions during secret fetch are handled gracefully."""
    # GIVEN: A relation where fetching secrets raises an exception
    model = MagicMock()
    relation = MagicMock()
    relation.id = 1
    relation.app = MagicMock()

    relation.data = {
        relation.app: {
            "config_yaml": config_with_inline_secret,
            "pipelines": json.dumps(["metrics"])
        }
    }
    model.relations.get.return_value = [relation]

    # Mock generic exception during secret fetch
    model.get_secret.side_effect = Exception("Connection error")

    requirer = OtelcolIntegratorRequirer(
        model=model,
        relation_name="external-config",
        secrets_dir="/tmp/secrets",
    )

    # WHEN: Retrieving external configs
    configs = requirer.retrieve_external_configs()

    # THEN: Relation is skipped due to secret resolution failure
    assert len(configs) == 0
