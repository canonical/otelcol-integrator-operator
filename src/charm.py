#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk


"""Charm the service."""

import logging
from typing import List, Optional

import ops
from charms.otelcol_integrator.v0.otelcol_integrator import (
    OtelcolIntegratorProviderRelationUpdater,
    OtelcolIntegratorProviderAppData,
    Pipeline,
    extract_secret_uris,
)
from cosl.reconciler import all_events, observe_events
from ops import ActiveStatus, BlockedStatus, CollectStatusEvent, StatusBase
from pydantic import ValidationError

from constants import (
    CONFIG_LOGS_PIPELINE,
    CONFIG_METRICS_PIPELINE,
    CONFIG_TRACES_PIPELINE,
    CONFIG_YAML_KEY,
    INVALID_RELATION_DATA_MSG,
    RELATION_ENDPOINT,
)
from secret_manager import SecretManager

logger = logging.getLogger(__name__)


class OtelcolIntegratorOperatorCharm(ops.CharmBase):
    """Integrator charm that shares configuration and secrets via external-config relation."""

    def __init__(self, framework: ops.Framework):
        super().__init__(framework)
        self._statuses: List[StatusBase] = []
        framework.observe(self.on.create_secret_action, self._on_create_secret_action)
        framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)
        observe_events(self, all_events, self._reconcile)

    def _reconcile(self, event) -> None:
        """Reconcile charm state on any event."""
        if not self.unit.is_leader():
            logger.debug("Not leader, skipping reconciliation")
            return

        config_yaml = str(self.config.get(CONFIG_YAML_KEY, ""))
        pipelines = self._retrieve_pipelines()

        relation_data = self._create_relation_data(config_yaml, pipelines)
        if relation_data is None:
            return  # Error status already set

        relations = self.model.relations.get(RELATION_ENDPOINT)
        if not relations:
            logger.debug("No %s relations found, skipping update", RELATION_ENDPOINT)
            # Configuration is valid, set active status
            msg = f"Pipelines: {', '.join(pipelines)} configured"
            self._statuses.append(ActiveStatus(msg))
            return

        self._process_secrets(config_yaml)
        self._update_relations(relations, relation_data, pipelines)

    def _create_relation_data(
        self, config_yaml: str, pipelines: List[str]
    ) -> Optional[OtelcolIntegratorProviderAppData]:
        """Create and validate relation data from config.

        Args:
            config_yaml: The YAML configuration string.
            pipelines: List of enabled pipeline names.

        Returns:
            OtelcolIntegratorProviderAppData if valid, None if validation fails.
        """
        try:
            return OtelcolIntegratorProviderAppData(
                config_yaml=config_yaml,
                pipelines=pipelines,
            )
        except ValidationError as e:
            error_msg = f"Invalid configuration: {e}"
            logger.warning(error_msg)
            self._statuses.append(BlockedStatus("Invalid configuration. Verify juju debug-logs"))
            return None

    def _process_secrets(self, config_yaml: str) -> None:
        """Grant secrets referenced in the configuration.

        Args:
            config_yaml: The YAML configuration string containing secret URIs.
        """
        secret_ids = extract_secret_uris(config_yaml)
        if secret_ids:
            logger.debug("Found %d secret URI(s) in configuration", len(secret_ids))

        sm = SecretManager(self.model, self.app)
        sm.grant_secrets(secret_ids)
        self._statuses.extend(sm.statuses)

    def _update_relations(
        self,
        relations: List[ops.Relation],
        relation_data: OtelcolIntegratorProviderAppData,
        pipelines: List[str],
    ) -> None:
        """Update all relations with the relation data.

        Args:
            relations: List of relations to update.
            relation_data: The relation data to publish.
            pipelines: List of enabled pipeline names for status message.
        """
        try:
            OtelcolIntegratorProviderRelationUpdater.update_relations_data(
                self.app,
                relations,
                relation_data,
            )
            logger.info("Updated %d relation(s) with config and secrets", len(relations))
            msg = f"Pipelines: {', '.join(pipelines)} configured"
            self._statuses.append(ActiveStatus(msg))
        except ValidationError as e:
            msg = f"Invalid relation data: {e}"
            logger.error(msg)
            self._statuses.append(BlockedStatus(INVALID_RELATION_DATA_MSG))

    def _on_collect_unit_status(self, event: CollectStatusEvent):
        """Handle `collect-status` event."""
        self._statuses.append(ActiveStatus())

        for status in self._statuses:
            event.add_status(status)

    def _on_create_secret_action(self, event: ops.ActionEvent):
        """Handle the create-secret action to create a new Juju secret."""
        sm = SecretManager(self.model, self.app)
        sm.create_secret(event)

    def _retrieve_pipelines(self) -> List[str]:
        """Retrieve the list of enabled pipelines from configuration.

        Returns:
            List of enabled pipeline names (metrics, logs, traces).
        """
        pipeline_mapping = {
            CONFIG_METRICS_PIPELINE: Pipeline.METRICS.value,
            CONFIG_LOGS_PIPELINE: Pipeline.LOGS.value,
            CONFIG_TRACES_PIPELINE: Pipeline.TRACES.value,
        }
        return [
            pipeline_name
            for config_key, pipeline_name in pipeline_mapping.items()
            if self.config.get(config_key, False)
        ]


if __name__ == "__main__":  # pragma: nocover
    ops.main(OtelcolIntegratorOperatorCharm)
