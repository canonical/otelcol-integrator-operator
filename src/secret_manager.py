# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk


"""Functions for interacting with the workload.

The intention is that this module could be used outside the context of a charm.
"""

import base64
import logging
from contextlib import suppress
from ops import BlockedStatus, StatusBase, SecretNotFoundError, ModelError
from typing import Dict, List, Set

from pydantic import BaseModel, field_validator

from constants import RELATION_ENDPOINT


logger = logging.getLogger(__name__)

def _is_base64_encoded(input_str: str) -> bool:
    """Check if a string is valid base64 encoded data.

    Args:
        input_str: String to check.

    Returns:
        True if string is valid base64, False otherwise.
    """
    if len(input_str) % 4 != 0:
        return False

    try:
        return base64.b64encode(base64.b64decode(input_str)) == input_str.encode('ascii')
    except Exception as e:
        logger.error("exception raised while base64 encoding and decoding: %s", e)
        return False


class SecretInfo(BaseModel):
    """Information required to create a Juju secret.

    Attributes:
        name: Label for the secret.
        data: Dictionary of key-value pairs to store in the secret.
    """

    name: str
    data: Dict[str, str]

    @field_validator("name")
    @classmethod
    def validate_name_not_empty(cls, v: str) -> str:
        """Validate that secret name is not empty.

        Args:
            v: The secret name to validate.

        Returns:
            The validated and trimmed secret name.

        Raises:
            ValueError: If secret name is empty or whitespace only.
        """
        if not v or not v.strip():
            raise ValueError("Secret name cannot be empty")
        return v.strip()

    @field_validator("data")
    @classmethod
    def validate_data_not_empty(cls, v: Dict[str, str]) -> Dict[str, str]:
        """Validate that secret data contains at least one key-value pair.

        Args:
            v: The secret data dictionary to validate.

        Returns:
            The validated secret data with base64 values decoded.

        Raises:
            ValueError: If data dictionary is empty.
        """
        if not v:
            raise ValueError("At least one key-value pair is required")
        return cls._decode_base64_values(v)

    @staticmethod
    def _decode_base64_values(data: Dict[str, str]) -> Dict[str, str]:
        """Process secret data by decoding base64-encoded values.

        Args:
            data: Dictionary of key-value pairs to process.

        Returns:
            Dictionary with base64 values decoded to plain text.
        """
        processed_data = dict(data)
        for key, value_str in processed_data.items():
            if _is_base64_encoded(value_str):
                with suppress(Exception):
                    decoded_bytes = base64.b64decode(value_str)
                    decoded_str = decoded_bytes.decode('utf-8')
                    processed_data[key] = decoded_str
                    logger.debug("Decoded base64 content for key: %s", key)
        return processed_data


class SecretManager:
    """Manages Juju secrets for the charm.

    Handles creation and granting of secrets to relations.
    """

    def __init__(self, model, app, relation_name: str = RELATION_ENDPOINT):
        self.model = model
        self.app = app
        self._relation_name = relation_name
        self.relations = self.model.relations.get(relation_name, [])
        self.statuses: List[StatusBase] = []

    def create_secret(self, secret_info: SecretInfo) -> str:
        """Create a new Juju secret.

        Args:
            secret_info: SecretInfo model containing name and data (already processed).

        Returns:
            The created secret ID.

        Raises:
            ValueError: If secret already exists.
        """
        if self._secret_exists(secret_info.name):
            msg = f"Secret '{secret_info.name}' already exists"
            logger.warning(msg)
            raise ValueError(msg)

        secret = self.app.add_secret(secret_info.data, label=secret_info.name)
        logger.info("Secret '%s' created with ID %s (keys: %s)",
                    secret_info.name, secret.id, ', '.join(secret_info.data.keys()))
        return secret.id


    def grant_secrets(self, secret_ids: Set[str]) -> None:
        """Grant secrets to all related charms.

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
                except ModelError as e:
                    logger.error("Failed to grant secret %s to relation %s: %s",
                                secret_uri, relation.id, e)
                    self.statuses.append(BlockedStatus(f"Failed to grant secret {secret_uri}"))

    def _secret_exists(self, name: str) -> bool:
        try:
            self.model.get_secret(label=name)
            return True
        except SecretNotFoundError:
            return False
