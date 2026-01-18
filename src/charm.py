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
from secrets import SecretManager, extract_secret_uris


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
        config_yaml = str(self.config.get("config_yaml", ""))
        pipelines = self._retrieve_pipelines()
        valid_config = self._validate_config(config_yaml, pipelines)

        if not self.unit.is_leader():
            return

        if not valid_config:
            return

        relations = self.model.relations.get("external-config")
        if not relations:
            return

        secret_ids = extract_secret_uris(config_yaml)

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
        """Validate the configuration.

        Args:
            config_yaml: The YAML configuration string to validate.
            pipelines: List of enabled pipelines.

        Returns:
            True if configuration is valid, False otherwise.
        """
        if not config_yaml:
            self._statuses.append(BlockedStatus("config_yaml setting is empty"))
            return False

        if not pipelines:
            self._statuses.append(BlockedStatus("at least one pipeline, metrics, logs or traces must be enabled"))
            return False

        msg = f"Pipelines: {', '.join(pipelines)} configured"
        self._statuses.append(ActiveStatus(msg))

        try:
            yaml.safe_load(config_yaml)
        except yaml.YAMLError as e:
            self._statuses.append(BlockedStatus("config_yaml is not valid YAML"))
            logger.error("config_yaml is not valid YAML: %s", e)
            return False

        return True

    def _retrieve_pipelines(self) -> list:
        """Retrieve the list of enabled pipelines from configuration.

        Returns:
            List of enabled pipeline names (metrics, logs, traces).
        """
        pipelines = []
        if self.config.get("metrics_pipeline", False):
            pipelines.append("metrics")
        if self.config.get("logs_pipeline", False):
            pipelines.append("logs")
        if self.config.get("traces_pipeline", False):
            pipelines.append("traces")
        return pipelines


if __name__ == "__main__":  # pragma: nocover
    ops.main(OtelcolIntegratorOperatorCharm)
