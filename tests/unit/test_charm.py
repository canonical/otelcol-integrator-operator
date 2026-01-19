# Copyright 2026 jose
# See LICENSE file for licensing details.
#
# To learn more about testing, see https://documentation.ubuntu.com/ops/latest/explanation/testing/

from unittest.mock import patch

from ops import testing



def test_install_without_config(ctx: testing.Context):
    """Test that charm is blocked when no config is provided."""
    # GIVEN: An empty configuration
    state_in = testing.State(leader=True, config={})

    # WHEN: Install event is triggered
    state_out = ctx.run(ctx.on.install(), state_in)

    # THEN: Charm should be blocked with appropriate message
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert "config_yaml setting is empty" in state_out.unit_status.message


def test_install_without_pipelines(ctx: testing.Context):
    """Test that charm is blocked when no pipelines are enabled."""
    # GIVEN: Config with YAML but no pipelines enabled
    state_in = testing.State(
        leader=True,
        config={
            "config_yaml": "key: value",
        },
    )

    # WHEN: Install event is triggered
    state_out = ctx.run(ctx.on.install(), state_in)

    # THEN: Charm should be blocked requiring at least one pipeline
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert "at least one pipeline" in state_out.unit_status.message


def test_install_with_invalid_yaml(ctx: testing.Context):
    """Test that charm is blocked when config_yaml is invalid YAML."""
    # GIVEN: Config with invalid YAML syntax
    state_in = testing.State(
        leader=True,
        config={
            "config_yaml": "key: [unclosed",
            "metrics_pipeline": True,
        },
    )

    # WHEN: Install event is triggered
    state_out = ctx.run(ctx.on.install(), state_in)

    # THEN: Charm should be blocked with YAML validation error
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert "not valid YAML" in state_out.unit_status.message


def test_install_with_valid_config_no_relation(ctx: testing.Context):
    """Test that charm is active with valid config but no relations."""
    # GIVEN: Valid configuration with pipelines enabled
    state_in = testing.State(
        leader=True,
        config={
            "config_yaml": "receivers:\n  otlp:\n    protocols:\n      grpc:\n",
            "metrics_pipeline": True,
            "logs_pipeline": True,
        },
    )

    # WHEN: Install event is triggered
    state_out = ctx.run(ctx.on.install(), state_in)

    # THEN: Charm should be active
    assert isinstance(state_out.unit_status, testing.ActiveStatus)


def test_relation_joined_updates_data(ctx: testing.Context):
    """Test that relation data is updated when a relation is joined."""
    # GIVEN: A relation and valid configuration
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

    # WHEN: Relation joined event is triggered
    state_out = ctx.run(ctx.on.relation_joined(relation), state_in)

    # THEN: Relation data should contain config and pipelines
    assert state_out.get_relation(relation.id)
    rel_out = state_out.get_relation(relation.id)
    assert "config_yaml" in rel_out.local_app_data
    assert "pipelines" in rel_out.local_app_data
    assert "metrics" in rel_out.local_app_data["pipelines"]
    assert "traces" in rel_out.local_app_data["pipelines"]


def test_config_changed_updates_relations(ctx: testing.Context):
    """Test that existing relations are updated when config changes."""
    # GIVEN: A relation with initial configuration
    relation = testing.Relation(
        endpoint="external-config",
        interface="external-config",
    )

    state_initial = ctx.run(
        ctx.on.config_changed(),
        testing.State(
            leader=True,
            relations={relation},
            config={
                "config_yaml": "old_config: initial_value",
                "metrics_pipeline": True,
            },
        ),
    )

    rel_initial = state_initial.get_relation(relation.id)
    assert "old_config: initial_value" in rel_initial.local_app_data["config_yaml"]
    assert "metrics" in rel_initial.local_app_data["pipelines"]

    # WHEN: Configuration is changed to new values
    state_out = ctx.run(
        ctx.on.config_changed(),
        testing.State(
            leader=True,
            relations={relation},
            config={
                "config_yaml": "new_config: changed_value",
                "logs_pipeline": True,
            },
        ),
    )

    # THEN: Relation data should be updated with new config
    rel_out = state_out.get_relation(relation.id)
    assert "new_config: changed_value" in rel_out.local_app_data["config_yaml"]
    assert "logs" in rel_out.local_app_data["pipelines"]
    assert "old_config" not in rel_out.local_app_data["config_yaml"]
    assert "metrics" not in rel_out.local_app_data["pipelines"]


def test_create_secret_action(ctx: testing.Context):
    """Test create-secret action creates a secret."""
    # GIVEN: A leader unit with no secrets
    state_in = testing.State(leader=True)

    # WHEN: Create-secret action is executed
    state_out = ctx.run(
        ctx.on.action(
            "create-secret", params={"name": "my-secret", "api-key": "secret-value-123"}
        ),
        state_in,
    )

    # THEN: A secret should be created with correct label and content
    secrets = list(state_out.secrets)
    assert len(secrets) == 1
    secret = secrets[0]
    assert secret.label == "my-secret"
    assert "api-key" in secret.tracked_content


def test_non_leader_does_nothing(ctx: testing.Context):
    """Test that non-leader units don't update relations."""
    # GIVEN: A non-leader unit with a relation and valid config
    relation = testing.Relation(
        endpoint="external-config",
        interface="external-config",
    )
    state_in = testing.State(
        leader=False,
        relations={relation},
        config={
            "config_yaml": "key: value",
            "metrics_pipeline": True,
        },
    )

    # WHEN: Config-changed event is triggered
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # THEN: Relation data should remain empty
    rel_out = state_out.get_relation(relation.id)
    assert not rel_out.local_app_data


def test_secret_uris_extracted_and_granted(ctx: testing.Context):
    """Test that secret URIs in config are extracted and granted to relations."""
    # GIVEN: A secret, a relation, and config containing a secret URI
    secret = testing.Secret(
        label="api-secret",
        owner="app",
        tracked_content={"token": "my-secret-token"},
    )

    relation = testing.Relation(
        endpoint="external-config",
        interface="external-config",
    )

    fake_secret_uri = "secret://8cec38a1-1c16-4d0e-8174-46aa32ee692d/d5ltigvmp25c762tsbr0"

    state_in = testing.State(
        leader=True,
        relations={relation},
        secrets={secret},
        config={
            "config_yaml": f"api_token: {fake_secret_uri}",
            "metrics_pipeline": True,
        },
    )

    # WHEN: Config-changed event is triggered
    state_out = ctx.run(ctx.on.config_changed(), state_in)

    # THEN: Secret URI should be extracted and added to relation data
    rel_out = state_out.get_relation(relation.id)
    assert "config_yaml" in rel_out.local_app_data
    assert fake_secret_uri in rel_out.local_app_data["config_yaml"]
    assert "secret_ids" in rel_out.local_app_data
    assert fake_secret_uri in rel_out.local_app_data["secret_ids"]


def test_config_changed_handles_validation_error(
    ctx: testing.Context, mock_pydantic_validation_error
):
    """Test that charm handles ValidationError when creating relation data."""
    # GIVEN: A valid state with relation and config
    relation = testing.Relation(
        endpoint="external-config",
        interface="external-config",
    )

    state_in = testing.State(
        leader=True,
        relations={relation},
        config={
            "config_yaml": "receivers:\n  otlp:\n    protocols:\n      grpc:",
            "metrics_pipeline": True,
        },
    )

    # WHEN: OtelcolIntegratorRelationData raises ValidationError
    with patch("charm.OtelcolIntegratorRelationData", side_effect=mock_pydantic_validation_error):
        state_out = ctx.run(ctx.on.config_changed(), state_in)

    # THEN: Charm should be blocked with validation error message
    assert isinstance(state_out.unit_status, testing.BlockedStatus)
    assert "Invalid relation data" in state_out.unit_status.message
