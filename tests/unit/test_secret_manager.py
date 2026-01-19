# Copyright 2026 jose
# See LICENSE file for licensing details.

"""Unit tests for secrets module."""

import base64
from unittest.mock import Mock

import pytest
from ops import testing

from charm import OtelcolIntegratorOperatorCharm
from secret_manager import SecretManager, _is_base64_encoded, extract_secret_uris


@pytest.fixture
def ctx():
    """Create a testing context for the charm."""
    return testing.Context(
        OtelcolIntegratorOperatorCharm,
        meta={
            "name": "otelcol-integrator",
            "provides": {
                "external-config": {
                    "interface": "external-config",
                }
            },
        },
        actions={
            "create-secret": {
                "description": "Create a Juju secret",
                "params": {
                    "name": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["name"],
            }
        },
        config={
            "options": {
                "config_yaml": {"type": "string", "default": ""},
                "metrics_pipeline": {"type": "boolean", "default": False},
            }
        },
    )


def test_create_secret_with_base64_value(ctx: testing.Context):
    """Test that base64 encoded values are decoded when creating secrets."""
    # GIVEN: A base64 encoded value
    plain_text = "my-secret-value"
    base64_value = base64.b64encode(plain_text.encode()).decode()

    # WHEN: Create-secret action is executed with base64 value
    state_out = ctx.run(
        ctx.on.action(
            "create-secret",
            params={"name": "base64-secret", "value": base64_value},
        ),
        testing.State(leader=True),
    )

    # THEN: Secret should be created and value should be decoded
    secrets = list(state_out.secrets)
    assert len(secrets) == 1
    secret = secrets[0]
    assert secret.label == "base64-secret"
    assert "value" in secret.tracked_content
    assert secret.tracked_content["value"] == plain_text


def test_create_secret_already_exists(ctx: testing.Context):
    """Test that creating a secret with existing name fails gracefully."""
    # GIVEN: A secret that already exists
    existing_secret = testing.Secret(
        label="existing-secret",
        owner="app",
        tracked_content={"key": "value"},
    )

    # WHEN: Attempting to create a secret with the same name
    # THEN: Action should fail with appropriate error
    with pytest.raises(testing.ActionFailed, match="already exists"):
        ctx.run(
            ctx.on.action(
                "create-secret",
                params={"name": "existing-secret", "value": "new-value"},
            ),
            testing.State(leader=True, secrets={existing_secret}),
        )


def test_create_secret_without_name_fails(ctx: testing.Context):
    """Test that create-secret action fails without name parameter."""
    # GIVEN: An action invocation without name parameter
    ctx_no_name = testing.Context(
        OtelcolIntegratorOperatorCharm,
        meta={
            "name": "otelcol-integrator",
            "provides": {"external-config": {"interface": "external-config"}},
        },
        actions={
            "create-secret": {
                "description": "Create a Juju secret",
                "params": {
                    "value": {"type": "string"},
                },
            }
        },
        config={
            "options": {
                "config_yaml": {"type": "string", "default": ""},
                "metrics_pipeline": {"type": "boolean", "default": False},
            }
        },
    )

    # WHEN/THEN: Create-secret is called without name, should fail
    with pytest.raises(testing.ActionFailed, match="Secret name is required"):
        ctx_no_name.run(
            ctx_no_name.on.action("create-secret", params={"value": "some-value"}),
            testing.State(leader=True),
        )


def test_create_secret_only_name_fails(ctx: testing.Context):
    """Test that create-secret fails with only name and no key-value pairs."""
    # GIVEN: Only a name parameter without any actual secret data
    # WHEN/THEN: Create-secret is called with only name, should fail
    with pytest.raises(testing.ActionFailed, match="At least one key-value pair"):
        ctx.run(
            ctx.on.action("create-secret", params={"name": "empty-secret"}),
            testing.State(leader=True),
        )


def test_create_secret_with_non_base64_value(ctx: testing.Context):
    """Test that non-base64 values are stored as-is."""
    # GIVEN: A regular (non-base64) string value
    plain_value = "just-a-regular-value"

    # WHEN: Create-secret action is executed
    state_out = ctx.run(
        ctx.on.action(
            "create-secret",
            params={"name": "plain-secret", "value": plain_value},
        ),
        testing.State(leader=True),
    )

    # THEN: Secret should be created with the original value
    secrets = list(state_out.secrets)
    assert len(secrets) == 1
    secret = secrets[0]
    assert secret.tracked_content["value"] == plain_value


def test_create_secret_with_invalid_base64(ctx: testing.Context):
    """Test that invalid base64 values are stored as-is."""
    # GIVEN: A string that looks like base64 but isn't valid
    invalid_base64 = "AAA"  # Not multiple of 4, invalid base64

    # WHEN: Create-secret action is executed
    state_out = ctx.run(
        ctx.on.action(
            "create-secret",
            params={"name": "invalid-base64-secret", "value": invalid_base64},
        ),
        testing.State(leader=True),
    )

    # THEN: Secret should be created with the original value (not decoded)
    secrets = list(state_out.secrets)
    assert len(secrets) == 1
    secret = secrets[0]
    assert secret.tracked_content["value"] == invalid_base64


def test_extract_secret_uris_from_yaml():
    """Test extraction of secret URIs from YAML config."""
    # GIVEN: Config YAML containing secret URI (note: regex only matches lowercase UUIDs)

    config_yaml = """
    receivers:
      prometheus:
        config:
          api_key: secret://8cec38a1-1c16-4d0e-8174-46aa32ee692d/d5ltigvmp25c762tsbr0/api_key?render=inline
    """

    # WHEN: Extracting secret URIs
    secret_uris = extract_secret_uris(config_yaml)

    # THEN: Secret URI should be extracted
    assert len(secret_uris) == 1
    assert "secret://8cec38a1-1c16-4d0e-8174-46aa32ee692d/d5ltigvmp25c762tsbr0" in secret_uris


def test_extract_secret_uris_no_secrets():
    """Test extraction when no secret URIs are present."""
    # GIVEN: Config YAML without any secret URIs

    config_yaml = """
    receivers:
      prometheus:
        config:
          api_key: plain-text-key
    """

    # WHEN: Extracting secret URIs
    secret_uris = extract_secret_uris(config_yaml)

    # THEN: No secret URIs should be found
    assert len(secret_uris) == 0


def test_is_base64_with_non_ascii_characters():
    """Test _is_base64_encoded with non-ASCII characters triggers exception."""
    # GIVEN: A string with non-ASCII characters that otherwise looks like base64
    non_ascii = "ÄÖÜß"  # These can't be encoded as ASCII

    # WHEN: Checking if it's base64 encoded
    result = _is_base64_encoded(non_ascii)

    # THEN: Should return False after catching exception
    assert result is False


def test_grant_secrets_no_relations():
    """Test grant_secrets with no relations configured."""
    # GIVEN: A SecretManager with no relations

    model = Mock()
    model.relations.get.return_value = []
    app = Mock()

    sm = SecretManager(model, app)

    # WHEN: Attempting to grant secrets
    sm.grant_secrets({"secret://abc-def/123"})

    # THEN: Should return early without errors
    assert len(sm.statuses) == 0


def test_grant_secrets_no_secret_ids():
    """Test grant_secrets with empty secret_ids set."""
    # GIVEN: A SecretManager with relations but no secret IDs

    model = Mock()
    relation = Mock()
    model.relations.get.return_value = [relation]
    app = Mock()

    sm = SecretManager(model, app)

    # WHEN: Attempting to grant empty set of secrets
    sm.grant_secrets(set())

    # THEN: Should return early without errors
    assert len(sm.statuses) == 0


def test_grant_secrets_generic_exception():
    """Test grant_secrets handles generic exceptions."""
    # GIVEN: A SecretManager with a relation that raises exception on grant

    model = Mock()
    relation = Mock()
    relation.id = 1
    model.relations.get.return_value = [relation]

    secret = Mock()
    secret.grant.side_effect = RuntimeError("Generic error")
    model.get_secret.return_value = secret

    app = Mock()
    sm = SecretManager(model, app)

    # WHEN: Attempting to grant secrets and exception occurs
    sm.grant_secrets({"secret://abc-def/123"})

    # THEN: Should handle exception and add to statuses
    assert len(sm.statuses) == 1
    assert "Failed to grant secret" in str(sm.statuses[0])


def test_process_secret_data_with_non_utf8_base64():
    """Test _process_secret_data with base64 that can't decode to UTF-8."""
    # GIVEN: A SecretManager

    model = Mock()
    app = Mock()
    sm = SecretManager(model, app)

    # Base64 that decodes to invalid UTF-8 (binary data)
    binary_base64 = "//79/Q=="  # This is valid base64 but not valid UTF-8

    # WHEN: Processing secret data with non-UTF-8 base64
    result = sm._process_secret_data({
        "name": "test-secret",
        "binary": binary_base64
    })

    # THEN: Should store original value when UTF-8 decode fails
    assert "binary" in result
    assert result["binary"] == binary_base64  # Falls back to original
