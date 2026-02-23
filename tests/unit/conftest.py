# Copyright 2026 jose
# See LICENSE file for licensing details.

"""Pytest fixtures for unit tests."""

import pytest
from ops import testing
from pydantic import BaseModel, ValidationError, field_validator

from charm import OtelcolIntegratorOperatorCharm


@pytest.fixture
def ctx():
    """Create a testing context for the charm.

    This fixture provides a configured ops.testing.Context instance
    with all necessary metadata, actions, and config options for testing
    the OtelcolIntegratorOperatorCharm.
    """
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
                    "api-key": {"type": "string"},
                    "token": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["name"],
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


@pytest.fixture
def mock_pydantic_validation_error():
    """Create a real Pydantic ValidationError for testing.

    Returns:
        A callable that raises a ValidationError when invoked.
    """

    def _raise_validation_error(*args, **kwargs):
        """Raise a ValidationError by creating an invalid model."""

        class _TestModel(BaseModel):
            value: str

            @field_validator("value")
            @classmethod
            def validate_value(cls, v):
                raise ValueError("Test validation error")

        try:
            _TestModel(value="test")
        except ValidationError as e:
            raise e

    return _raise_validation_error
