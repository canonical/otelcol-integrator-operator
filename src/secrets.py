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

logger = logging.getLogger(__name__)

RELATION_NAME = "external-config"

def _is_base64_encoded(sb: str):
    # Check if the string length is a multiple of 4
    if len(sb) % 4 != 0:
        return False

    # Check if the string contains only Base64 characters
    if not re.fullmatch(r'[A-Za-z0-9+/]*={0,2}', sb):
        return False

    sb_bytes = bytes(sb, 'ascii')

    try:
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception as e:
        logger.warning(e)
        return False

def extract_secret_uris(config_yaml: str) -> Set[str]:
    """Extract all secret URIs from the config YAML.

    Searches for secret URIs in the format: secret://model-uuid/secret-id

    Args:
        config_yaml: YAML configuration text that may contain secret URIs

    Returns:
        Set of unique secret URIs in the format secret://model-uuid/secret-id
    """
    secret_pattern = re.compile(r'secret://[a-f0-9-]+/[a-z0-9]+')
    return set(secret_pattern.findall(config_yaml))


class SecretManager:
    """Manages Juju secrets for the charm.

    Handles creation and granting of secrets to relations.
    """

    def __init__(self, model, app, relation_name: str = RELATION_NAME):
        self.model = model
        self.app = app
        self.relations = model.relations.get(relation_name, [])
        self.statuses: List[StatusBase] = []

    def create_secret(self, event: ActionEvent):
        """Create a new Juju secret from action parameters.

        Args:
            event: The action event containing secret name and key-value pairs.

        Returns:
            True if secret was created successfully, False otherwise.
        """
        if not self._validate_key_value_pairs(event):
            return False

        secret_name = str(event.params.get("name"))

        if self._secret_exists(secret_name):
            msg = f"failed to create secret: {secret_name} already exists"
            event.fail(msg)
            logger.error(msg)
            return False

        secret_data = self._process_secret_data(event.params)
        secret = self.app.add_secret(secret_data, label=secret_name)
        msg = f"secret {secret_name} with ID {secret.id} created with keys: {','.join(secret_data.keys())}"
        logger.info(msg)
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
        if not self.relations:
            return

        if not secret_ids:
            return

        for relation in self.relations:
            for secret_uri in secret_ids:
                try:
                    secret = self.model.get_secret(id=secret_uri)
                    secret.grant(relation)
                    logger.info("Granted secret %s to relation %s", secret_uri, relation.id)
                except SecretNotFoundError:
                    msg = f"secret {secret_uri} not found"
                    logger.error(msg)
                    self.statuses.append(BlockedStatus(msg))
                except Exception as e:
                    logger.error("Failed to grant secret %s: %s", secret_uri, e)
                    self.statuses.append(BlockedStatus(f"Failed to grant secret {secret_uri}"))

        return


    def _validate_key_value_pairs(self, event: ActionEvent) -> bool:
        if not event.params.get("name"):
            event.fail("Secret name is required")
            return False

        processed_data = {}
        for key, value in event.params.items():
            if key == "name":
                continue
            value_str = str(value)
            processed_data[key] = value_str

        if not processed_data:
            event.fail("At least one key-value pair is required besides 'name'")
            return False

        return True

    def _process_secret_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process secret data, decoding base64 values if needed."""
        processed_data = {}
        for key, value in data.items():
            if key == "name":
                continue

            value_str = str(value)
            processed_data[key] = value_str

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
