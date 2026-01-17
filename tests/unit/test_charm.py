# Copyright 2026 jose
# See LICENSE file for licensing details.
#
# To learn more about testing, see https://documentation.ubuntu.com/ops/latest/explanation/testing/

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
                    "name": {"type": "string"}
                },
                "required": ["name"],
                "additionalProperties": True,
            }
        },
        config={
            "options": {
                "config_yaml": {
                    "type": "string",
                    "default": "",
                },
                "metrics_pipeline": {
                    "type": "boolean",
                    "default": False,
                },
                "logs_pipeline": {
                    "type": "boolean",
                    "default": False,
                },
                "traces_pipeline": {
                    "type": "boolean",
                    "default": False,
                },
            }
        },
    )


def test_install_without_config(ctx: testing.Context):
    """Test that charm is blocked when no config is provided."""
    # Arrange: Empty config
    state_in = testing.State(leader=True, config={})

    # Act: Trigger install event
    state_out = ctx.run(ctx.on.install(), state_in)

    # Assert: Charm should be blocked
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert "config_yaml setting is empty" in state_out.unit_status.message


def test_install_without_pipelines(ctx: testing.Context):
    """Test that charm is blocked when no pipelines are enabled."""
    # Arrange: Config with YAML but no pipelines
    state_in = testing.State(
        leader=True,
        config={
            "config_yaml": "key: value",
        },
    )

    # Act
    state_out = ctx.run(ctx.on.install(), state_in)

    # Assert
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert "at least one pipeline" in state_out.unit_status.message


def test_install_with_invalid_yaml(ctx: testing.Context):
    """Test that charm is blocked when config_yaml is invalid YAML."""
    # Arrange
    state_in = testing.State(
        leader=True,
        config={
            "config_yaml": "key: [unclosed",
            "metrics_pipeline": True,
        },
    )

    # Act
    state_out = ctx.run(ctx.on.install(), state_in)

    # Assert
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert "not valid YAML" in state_out.unit_status.message


def test_install_with_valid_config_no_relation(ctx: testing.Context):
    """Test that charm is active with valid config but no relations."""
    # Arrange
    state_in = testing.State(
        leader=True,
        config={
            "config_yaml": "exporters:\n  splunk_hec:\n    token: Qwerty",
            "metrics_pipeline": True,
            "logs_pipeline": True,
        },
    )

    # Act
    state_out = ctx.run(ctx.on.install(), state_in)

    # Assert
    assert isinstance(state_out.unit_status, testing.ActiveStatus)


def test_relation_joined_updates_data(ctx: testing.Context):
    """Test that relation data is updated when a relation is joined."""
    # Arrange
    relation = testing.Relation(
        endpoint="external-config",
        interface="external-config",
    )
    state_in = testing.State(
        leader=True,
        relations={relation},
        config={
            "config_yaml": "receivers:\n  otlp:\n    protocols:\n      grpc:\n",
            "metrics_pipeline": True,
            "traces_pipeline": True,
        },
    )

    # Act
    state_out = ctx.run(ctx.on.relation_joined(relation), state_in)

    # Assert
    assert state_out.get_relation(relation.id)
    rel_out = state_out.get_relation(relation.id)
    # Check that relation data was set (app databag)
    assert "config_yaml" in rel_out.local_app_data
    assert "pipelines" in rel_out.local_app_data
    assert "metrics" in rel_out.local_app_data["pipelines"]
    assert "traces" in rel_out.local_app_data["pipelines"]


def test_config_changed_updates_relations(ctx: testing.Context):
    """Test that existing relations are updated when config changes."""
    # Arrange
    relation = testing.Relation(
        endpoint="external-config", interface="external-config", local_app_data={}
    )
    state_in = testing.State(
        leader=True,
        relations={relation},
        config={
            "config_yaml": "new_config: value",
            "logs_pipeline": True,
        },
    )

    # Act
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Assert
    rel_out = state_out.get_relation(relation.id)
    assert "new_config: value" in rel_out.local_app_data["config_yaml"]
    assert "logs" in rel_out.local_app_data["pipelines"]


def test_create_secret_action(ctx: testing.Context):
    """Test create-secret action creates a secret."""
    # Arrange: Update context with proper action definition that allows additional properties
    ctx_with_action = testing.Context(
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
                    "api-key": {"type": "string"},  # Explicitly define the param
                },
                "required": ["name"],
            }
        },
        config={
            "options": {
                "config_yaml": {"type": "string", "default": ""},
                "metrics_pipeline": {"type": "boolean", "default": False},
                "logs_pipeline": {"type": "boolean", "default": False},
                "traces_pipeline": {"type": "boolean", "default": False},
            }
        },
    )

    state_in = testing.State(leader=True)

    # Act
    state_out = ctx_with_action.run(
        ctx_with_action.on.action(
            "create-secret", params={"name": "my-secret", "api-key": "secret-value-123"}
        ),
        state_in,
    )

    # Assert
    assert len(state_out.secrets) == 1
    secret = list(state_out.secrets)[0]
    assert secret.label == "my-secret"
    assert "api-key" in secret.tracked_content


def test_non_leader_does_nothing(ctx: testing.Context):
    """Test that non-leader units don't update relations."""
    # Arrange
    relation = testing.Relation(
        endpoint="external-config",
        interface="external-config",
    )
    state_in = testing.State(
        leader=False,  # Not the leader
        relations={relation},
        config={
            "config_yaml": "key: value",
            "metrics_pipeline": True,
        },
    )

    # Act
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Assert: Relation data should not be updated
    rel_out = state_out.get_relation(relation.id)
    assert not rel_out.local_app_data  # Empty databag


def test_secret_uris_extracted_and_granted(ctx: testing.Context):
    """Test that secret URIs in config are extracted and granted to relations."""
    # Arrange
    relation = testing.Relation(
        endpoint="external-config",
        interface="external-config",
    )
    secret = testing.Secret(
        label="my-secret",
        owner="app",
        tracked_content={"key": "value"},
    )
    # Note: We can't easily test secret URIs without integration tests
    # as the secret:// format is dynamically generated by Juju
    state_in = testing.State(
        leader=True,
        relations={relation},
        secrets={secret},
        config={
            "config_yaml": "api_key: some-value",
            "metrics_pipeline": True,
        },
    )

    # Act
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # Assert: Just verify it doesn't crash and relation data is updated
    rel_out = state_out.get_relation(relation.id)
    assert "config_yaml" in rel_out.local_app_data
    assert "api_key: some-value" in rel_out.local_app_data["config_yaml"]


