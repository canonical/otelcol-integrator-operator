#!/usr/bin/env python3
# Copyright 2026 jose
# See LICENSE file for licensing details.

"""Charm the application."""

import logging
from typing import List

import ops
import yaml

from cosl.reconciler import all_events, observe_events
from ops import ActiveStatus, BlockedStatus, StatusBase, CollectStatusEvent
from pydantic import ValidationError
from charms.otelcol_integrator.v0.otelcol_integrator import (
    OtelcolIntegratorProviderRelationUpdater,
    OtelcolIntegratorRelationData,
)
from secret_manager import SecretManager, extract_secret_uris
from constants import (
    RELATION_ENDPOINT,
    CONFIG_YAML_KEY,
    CONFIG_METRICS_PIPELINE,
    CONFIG_LOGS_PIPELINE,
    CONFIG_TRACES_PIPELINE,
    Pipeline,
)


logger = logging.getLogger(__name__)


class OtelcolIntegratorOperatorCharm(ops.CharmBase):
    """Integrator charm that shares configuration and secrets via external-config relation."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._statuses: List[StatusBase] = []
        framework.observe(self.on.create_secret_action, self._on_create_secret_action)
        framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        observe_events(self, all_events, self._reconcile)

    def _reconcile(self, event):
        """Reconcile charm state on any event."""
        config_yaml = str(self.config.get(CONFIG_YAML_KEY, ""))
        pipelines = self._retrieve_pipelines()
        valid_config = self._validate_config(config_yaml, pipelines)

        if not self.unit.is_leader():
            logger.debug("Not leader, skipping reconciliation")
            return

        if not valid_config:
            logger.warning("Invalid configuration, skipping relation update")
            return

        relations = self.model.relations.get(RELATION_ENDPOINT)
        if not relations:
            logger.debug("No %s relations found, skipping update", RELATION_ENDPOINT)
            return

        secret_ids = extract_secret_uris(config_yaml)
        if secret_ids:
            logger.debug("Found %d secret URI(s) in configuration", len(secret_ids))

        sm = SecretManager(self.model, self.app)
        sm.grant_secrets(secret_ids)
        self._statuses.extend(sm.statuses)

        try:
            relation_data = OtelcolIntegratorRelationData(
                config_yaml=config_yaml,
                secret_ids=secret_ids,
                pipelines=pipelines,
            )
            OtelcolIntegratorProviderRelationUpdater.update_relations_data(
                self.app,
                relations,
                relation_data,
            )
            logger.info("Updated %d relation(s) with config and secrets", len(relations))
        except ValidationError as e:
            msg = f"Invalid relation data: {e}"
            logger.error(msg)
            self._statuses.append(BlockedStatus(msg))

    def _on_collect_unit_status(self, event: CollectStatusEvent):
        """Handle `collect-status` event."""
        self._statuses.append(ActiveStatus())

        for status in self._statuses:
            event.add_status(status)

    def _on_create_secret_action(self, event: ops.ActionEvent):
        """Handle the create-secret action to create a new Juju secret."""
        sm = SecretManager(self.model, self.app)
        sm.create_secret(event)

    def _validate_config(self, config_yaml: str, pipelines: list) -> bool:
        """Validate the configuration and update status.

        Args:
            config_yaml: The YAML configuration string to validate.
            pipelines: List of enabled pipelines.

        Returns:
            True if configuration is valid, False otherwise.
        """
        # Perform validation
        is_valid, error_msg = self._check_config_validity(config_yaml, pipelines)

        # Update status based on validation result
        if not is_valid:
            self._statuses.append(BlockedStatus(error_msg))
            return False

        msg = f"Pipelines: {', '.join(pipelines)} configured"
        self._statuses.append(ActiveStatus(msg))
        return True

    def _check_config_validity(self, config_yaml: str, pipelines: list) -> tuple[bool, str]:
        """Check configuration validity without side effects.

        Args:
            config_yaml: The YAML configuration string to validate.
            pipelines: List of enabled pipelines.

        Returns:
            Tuple of (is_valid, error_message). error_message is empty if valid.
        """
        if not config_yaml:
            return False, f"{CONFIG_YAML_KEY} setting is empty"

        if not pipelines:
            return False, f"at least one pipeline ({Pipeline.METRICS}, {Pipeline.LOGS} or {Pipeline.TRACES}) must be enabled"

        try:
            yaml.safe_load(config_yaml)
        except yaml.YAMLError as e:
            logger.error("Invalid YAML in %s: %s", CONFIG_YAML_KEY, e)
            return False, f"{CONFIG_YAML_KEY} is not valid YAML"

        return True, ""

    def _retrieve_pipelines(self) -> List[str]:
        """Retrieve the list of enabled pipelines from configuration.

        Returns:
            List of enabled pipeline names (metrics, logs, traces).
        """
        pipelines = []
        if self.config.get(CONFIG_METRICS_PIPELINE, False):
            pipelines.append(Pipeline.METRICS.value)
        if self.config.get(CONFIG_LOGS_PIPELINE, False):
            pipelines.append(Pipeline.LOGS.value)
        if self.config.get(CONFIG_TRACES_PIPELINE, False):
            pipelines.append(Pipeline.TRACES.value)
        return pipelines


if __name__ == "__main__":  # pragma: nocover
    ops.main(OtelcolIntegratorOperatorCharm)
