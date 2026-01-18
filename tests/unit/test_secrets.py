# Copyright 2026 jose
# See LICENSE file for licensing details.

"""Unit tests for secrets module."""

import base64
import pytest
from ops import testing

from charm import OtelcolIntegratorOperatorCharm


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
    assert len(state_out.secrets) == 1
    secret = list(state_out.secrets)[0]
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
    assert len(state_out.secrets) == 1
    secret = list(state_out.secrets)[0]
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
    assert len(state_out.secrets) == 1
    secret = list(state_out.secrets)[0]
    assert secret.tracked_content["value"] == invalid_base64


def test_extract_secret_uris_from_yaml():
    """Test extraction of secret URIs from YAML config."""
    # GIVEN: Config YAML containing secret URI (note: regex only matches lowercase UUIDs)
    from secrets import extract_secret_uris

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
    from secrets import extract_secret_uris

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
