#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk


"""OtelcolIntegrator charm library.

This library provides utilities for integrating with the Otelcol collector
through the external-config relation.
"""

import json
import logging
import re

from typing import List, Set

import yaml
from pydantic import BaseModel, field_validator
from ops import Application, Relation

logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "CHANGE-ME!!"

# Increment this major API version when introducing breaking changes
LIBAPI = 0
# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

SECRET_URI_PATTERN = r'secret://[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/[a-z0-9]{20}'

def extract_secret_uris(config_yaml: str) -> Set[str]:
    """Extract all secret URIs from the config YAML.

    Searches for secret URIs in the format: secret://model-uuid/secret-id

    Args:
        config_yaml: YAML configuration text that may contain secret URIs

    Returns:
        Set of unique secret URIs in the format secret://model-uuid/secret-id
    """
    secret_pattern = re.compile(SECRET_URI_PATTERN)
    return set(secret_pattern.findall(config_yaml))

class OtelcolIntegratorRelationData(BaseModel):
    """Model representing data shared through external-config relation.

    Attributes:
        config_yaml: OpenTelemetry Collector YAML configuration.
        secret_ids: Set of Juju secret URIs referenced in the configuration.
        pipelines: List of enabled pipeline names (metrics, logs, traces).
    """

    config_yaml: str
    secret_ids: Set[str] = set()
    pipelines: List[str]

    @field_validator("config_yaml")
    @classmethod
    def validate_yaml(cls, v: str) -> str:
        """Validate that config_yaml is valid YAML.

        Args:
            v: The config_yaml string to validate.

        Returns:
            The validated config_yaml string.

        Raises:
            ValueError: If the YAML is empty or invalid.
        """
        if not v or not v.strip():
            raise ValueError("config_yaml cannot be empty")
        try:
            yaml.safe_load(v)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
        return v

    @field_validator("pipelines")
    @classmethod
    def validate_pipelines(cls, v: List[str]) -> List[str]:
        """Validate pipelines contains only valid values.

        Args:
            v: List of pipeline names to validate.

        Returns:
            The validated list of pipeline names.

        Raises:
            ValueError: If pipelines are invalid or empty.
        """
        valid = {"metrics", "logs", "traces"}
        invalid = set(v) - valid
        if invalid:
            raise ValueError(f"Invalid pipelines: {invalid}. Must be one of {valid}")
        if not v:
            raise ValueError("At least one pipeline must be enabled")
        return v


class OtelcolIntegratorProviderRelationUpdater:
    """Updates relation data for Otelcol integrator provider relations."""

    @staticmethod
    def update_relations_data(
        application: Application,
        relations: List[Relation],
        data: OtelcolIntegratorRelationData,
    ) -> None:
        """Update relation data with validated configuration.

        Args:
            application: The application object to use for relation data.
            relations: List of relations to update.
            data: Validated relation data model.
        """
        if not relations:
            return

        for relation in relations:
            relation.data[application]["config_yaml"] = data.config_yaml
            relation.data[application]["pipelines"] = json.dumps(data.pipelines)
            relation.data[application]["secret_ids"] = ",".join(data.secret_ids)
            logger.info("Updated relation %s with config and secrets", relation.id)
