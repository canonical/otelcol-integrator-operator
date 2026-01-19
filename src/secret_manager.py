# Copyright 2026 Canonical
# See LICENSE file for licensing details.

"""Functions for interacting with the workload.

The intention is that this module could be used outside the context of a charm.
"""

import base64
import logging
import re
from ops import ActionEvent, BlockedStatus, StatusBase, SecretNotFoundError
from typing import Any, Dict, List, Set

from constants import RELATION_ENDPOINT, SECRET_PARAM_NAME
from charms.otelcol_integrator.v0.otelcol_integrator import SECRET_URI_PATTERN


logger = logging.getLogger(__name__)

def _is_base64_encoded(sb: str) -> bool:
    """Check if a string is valid base64 encoded data.

    Args:
        sb: String to check.

    Returns:
        True if string is valid base64, False otherwise.
    """
    if len(sb) % 4 != 0:
        return False

    if not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', sb):
        return False

    try:
        return base64.b64encode(base64.b64decode(sb)) == sb.encode('ascii')
    except Exception as e:
        logger.error("exception raised while base64 encoding and decoding: %s", e)
        return False

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


class SecretManager:
    """Manages Juju secrets for the charm.

    Handles creation and granting of secrets to relations.
    """

    def __init__(self, model, app, relation_name: str = RELATION_ENDPOINT):
        self.model = model
        self.app = app
        self._relation_name = relation_name
        self._relations = None
        self.statuses: List[StatusBase] = []

    @property
    def relations(self):
        """Lazy-load relations when first accessed."""
        if self._relations is None:
            self._relations = self.model.relations.get(self._relation_name, [])
        return self._relations

    def create_secret(self, event: ActionEvent):
        """Create a new Juju secret from action parameters.

        Args:
            event: The action event containing secret name and key-value pairs.

        Returns:
            True if secret was created successfully, False otherwise.
        """
        if not self._validate_key_value_pairs(event):
            return False

        secret_name = str(event.params.get(SECRET_PARAM_NAME))

        if self._secret_exists(secret_name):
            msg = f"Secret '{secret_name}' already exists"
            event.fail(msg)
            logger.warning(msg)
            return False

        secret_data = self._process_secret_data(event.params)
        secret = self.app.add_secret(secret_data, label=secret_name)
        logger.info("Secret '%s' created with ID %s (keys: %s)",
                    secret_name, secret.id, ', '.join(secret_data.keys()))
        event.set_results({
            "secret-id": secret.id,
            "keys": ",".join(secret_data.keys())
        })
        return True


    def grant_secrets(self, secret_ids: Set[str]) -> None:
        """Grant secrets to all relations.

        Populates self.statuses with any errors that occur during granting.

        Args:
            secret_ids: Set of secret URIs to grant.
        """
        if not self.relations or not secret_ids:
            return

        for relation in self.relations:
            for secret_uri in secret_ids:
                try:
                    secret = self.model.get_secret(id=secret_uri)
                    secret.grant(relation)
                    logger.info("Granted secret %s to relation %s", secret_uri, relation.id)
                except SecretNotFoundError:
                    msg = f"Secret {secret_uri} not found"
                    logger.error(msg)
                    self.statuses.append(BlockedStatus(msg))
                except Exception as e:
                    logger.error("Failed to grant secret %s to relation %s: %s",
                                secret_uri, relation.id, e)
                    self.statuses.append(BlockedStatus(f"Failed to grant secret {secret_uri}"))


    def _extract_secret_params(self, params: Dict[str, Any]) -> Dict[str, str]:
        """Extract secret parameters, excluding the name parameter.

        Args:
            params: Dictionary of parameters from action event.

        Returns:
            Dictionary of key-value pairs with name parameter excluded.
        """
        return {k: str(v) for k, v in params.items() if k != SECRET_PARAM_NAME}

    def _validate_key_value_pairs(self, event: ActionEvent) -> bool:
        if not event.params.get(SECRET_PARAM_NAME):
            event.fail(f"Secret {SECRET_PARAM_NAME} is required")
            return False

        processed_data = self._extract_secret_params(event.params)

        if not processed_data:
            event.fail(f"At least one key-value pair is required besides '{SECRET_PARAM_NAME}'")
            return False

        return True

    def _process_secret_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process secret data, decoding base64 values if needed."""
        processed_data = self._extract_secret_params(data)

        # Attempt to decode base64 values
        for key, value_str in processed_data.items():
            if _is_base64_encoded(value_str):
                try:
                    decoded_bytes = base64.b64decode(value_str)
                    decoded_str = decoded_bytes.decode('utf-8')
                    processed_data[key] = decoded_str
                    logger.debug("Decoded base64 content for key: %s", key)
                except Exception:
                    pass

        return processed_data

    def _secret_exists(self, name: str) -> bool:
        try:
            self.model.get_secret(label=name)
            return True
        except SecretNotFoundError:
            return False
