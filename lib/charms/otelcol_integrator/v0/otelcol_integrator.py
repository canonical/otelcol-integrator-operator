# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more at: https://juju.is/docs/sdk


"""OtelcolIntegrator charm library.

This library provides utilities for integrating with the Otelcol Integrator Charm
through the external-config relation. It supports sharing configuration and secrets
between charms.

## Overview

This library provides three main components:

- **OtelcolIntegratorProviderAppData**: Data model for validation
- **OtelcolIntegratorProviderRelationUpdater**: Provider-side relation updates
- **OtelcolIntegratorRequirer**: Requirer-side configuration retrieval

## Usage

### Provider Side (Sharing Configuration)

Use this side when your charm provides OpenTelemetry Collector configuration
to other charms.

```python
from charms.otelcol_integrator.v0.otelcol_integrator import (
    OtelcolIntegratorProviderAppData,
    OtelcolIntegratorProviderRelationUpdater,
)

# 1. Create and validate your configuration data
config_data = OtelcolIntegratorProviderAppData(
    config_yaml='''
exporters:
  splunk_hec:
    token: "secret://model-uuid/secret-id/token?render=inline"
    endpoint: "https://splunk:8088/services/collector"
    ''',
    pipelines=["metrics", "logs"]
)

# 2. Update all relations with the configuration
relations = self.model.relations.get("external-config", [])
OtelcolIntegratorProviderRelationUpdater.update_relations_data(
    application=self.app,
    relations=relations,
    data=config_data
)
```

**Secret URI Format:**
- Inline secrets: `secret://model-uuid/secret-id/key?render=inline`
- File-based secrets: `secret://model-uuid/secret-id/key?render=file`

### Requirer Side (Consuming Configuration)

Use this side when your charm consumes OpenTelemetry Collector configuration
from another charm.

```python
from charms.otelcol_integrator.v0.otelcol_integrator import (
    OtelcolIntegratorRequirer,
)

# 1. Initialize the requirer
self.requirer = OtelcolIntegratorRequirer(
    model=self.model,
    relation_name="external-config",
    secrets_dir="/etc/otelcol/secrets"  # Where secret files should go
)

# 2. Retrieve configurations from all relations
configs = self.requirer.retrieve_external_configs()

# configs is a list of dicts:
# [
#     {
#         "config_yaml": "...",  # Secrets resolved to values or paths
#         "pipelines": ["metrics", "logs"]
#     }
# ]

# 3. Write secret files to disk (library only generates paths/content)
```

**Important Notes:**
- The library does NOT write files to disk
- It only provides file paths and content
- The charm is responsible for writing files
- Secret URIs are automatically replaced with values or file paths

## Data Validation

The `OtelcolIntegratorProviderAppData` model automatically validates:

- **config_yaml**: Must be valid YAML
- **Secret URIs**: Must follow format `secret://<model-uuid>/<secret-id>/<key>?render=<inline|file>`
- **pipelines**: Must be one of: "metrics", "logs", "traces"

Invalid data will raise a `ValidationError` with a descriptive message.

## Examples

### Provider with Inline Secret

```python
# The secret token will be fetched and embedded directly in the config
config_data = OtelcolIntegratorProviderAppData(
    config_yaml='''
receivers:
  prometheus:
    config:
      scrape_configs:
        - bearer_token: "secret://model-uuid/secret-id/token?render=inline"
    ''',
    pipelines=["metrics"]
)
```

### Provider with File-based Secret

```python
# The secret will be written to a file, path replaces the URI
config_data = OtelcolIntegratorProviderAppData(
    config_yaml='''
exporters:
  otlp:
    tls:
      cert_file: "secret://model-uuid/secret-id/cert?render=file"
      key_file: "secret://model-uuid/secret-id/key?render=file"
    ''',
    pipelines=["traces"]
)
```

### Requirer Processing Multiple Relations

```python
# Get configs from all related charms
configs = self.requirer.retrieve_external_configs()

# Merge or process each config
for config in configs:
    yaml_config = yaml.safe_load(config["config_yaml"])
    pipelines = config["pipelines"]

    # Process configuration...

# Write secret files
for file_path, content in self.requirer.secret_files.items():
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    Path(file_path).write_text(content)
```
"""

import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Dict, List, Set, Literal, Any, Optional
from urllib.parse import urlparse, parse_qs

import yaml
from pydantic import BaseModel, field_validator
from ops import Application, Model, ModelError, Relation, SecretNotFoundError

logger = logging.getLogger(__name__)

# The unique Charmhub library identifier, never change it
LIBID = "CHANGE-ME!!"

# Increment this major API version when introducing breaking changes
LIBAPI = 0
# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1

# Base pattern for secret URIs: secret://model-uuid/secret-id
SECRET_URI_PATTERN = r'secret://[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/[a-z0-9]{20}'
SECRET_URI_PATTERN_COMP = re.compile(SECRET_URI_PATTERN)

# Extended pattern to match secret URIs with optional key and query string
# Format: secret://model-uuid/secret-id[/key][?query]
SECRET_URI_PATTERN_EXTENDED = SECRET_URI_PATTERN + r'(?:/[a-z0-9_-]+)?(?:\?[^\s"\']*)?'
SECRET_URI_PATTERN_EXTENDED_COMP = re.compile(SECRET_URI_PATTERN_EXTENDED)


# ============================================================================
# PUBLIC API - Use these classes in your charm
# ============================================================================

class Pipeline(str, Enum):
    """OpenTelemetry Collector pipeline types."""

    METRICS = "metrics"
    LOGS = "logs"
    TRACES = "traces"


class SecretURI(BaseModel):
    """Represents a validated Juju secret URI with key and render mode.

    Format: secret://<model-uuid>/<secret-id>/<key>?render=<inline|file>

    This class encapsulates the validation logic for secret URIs used in
    OpenTelemetry Collector configurations. It ensures that secret references
    are well-formed and contain all required components.

    Attributes:
        model_uuid: The Juju model UUID.
        secret_id: The Juju secret ID.
        key: The key within the secret to access.
        render: How to render the secret ('inline' or 'file').

    Example:
        >>> uri = "secret://model-uuid-123/secret-456/token?render=inline"
        >>> secret = SecretURI.from_uri(uri)
        >>> secret.model_uuid
        'model-uuid-123'
        >>> secret.secret_id
        'secret-456'
        >>> secret.key
        'token'
        >>> secret.render
        'inline'
    """

    model_uuid: str
    secret_id: str
    key: str
    render: Literal["inline", "file"]

    @staticmethod
    def _parse_secret_uri(uri: str) -> Dict[str, Any]:
        """Parse a Juju secret URI into its components.

        Args:
            uri: Secret URI in format secret://<model-uuid>/<secret-id>/<key>?render=<inline|file>

        Returns:
            Dictionary with 'key' and 'query' components.

        Raises:
            ValueError: If URI scheme is not 'secret://' or format is invalid.
        """
        if not uri.startswith("secret://"):
            raise ValueError(f"Secret URI must start with 'secret://': {uri}")

        # Parse URL components
        parsed = urlparse(uri)

        # Extract key from path (must have at least 2 components: secret-id and key)
        path_parts = [p for p in parsed.path.split('/') if p]
        if len(path_parts) < 2:
            key = None
        else:
            key = path_parts[-1]  # Last component is the key

        # Parse query parameters
        query_params = parse_qs(parsed.query)
        query_dict = {k: v[0] if len(v) == 1 else v for k, v in query_params.items()}

        return {
            "key": key,
            "query": query_dict,
        }

    @classmethod
    def from_uri(cls, uri: str) -> "SecretURI":
        """Parse and validate a secret URI string.

        Args:
            uri: Secret URI string to parse.

        Returns:
            Validated SecretURI instance.

        Raises:
            ValueError: If URI format is invalid or missing required parts.
        """
        parsed = cls._parse_secret_uri(uri)

        if parsed["key"] is None:
            raise ValueError(f"Secret URI must include a key: {uri}")
        if "render" not in parsed["query"]:
            raise ValueError(f"Secret URI must include render query parameter: {uri}")

        render_value = parsed["query"]["render"]
        if render_value not in ("inline", "file"):
            raise ValueError(
                f"Secret URI render parameter must be 'inline' or 'file': {uri}"
            )

        # Extract model_uuid and secret_id from the URI
        # Format: secret://<model-uuid>/<secret-id>/<key>?render=<inline|file>
        url_parsed = urlparse(uri)
        model_uuid = url_parsed.netloc
        path_components = [p for p in url_parsed.path.split('/') if p]
        secret_id = path_components[0] if path_components else ""

        return cls(
            model_uuid=model_uuid,
            secret_id=secret_id,
            key=parsed["key"],
            render=render_value,
        )

    def to_uri(self) -> str:
        """Convert back to URI string format.

        Returns:
            The secret URI as a string.
        """
        return f"secret://{self.model_uuid}/{self.secret_id}/{self.key}?render={self.render}"


class OtelcolIntegratorProviderAppData(BaseModel):
    """Model representing data shared through external-config relation.

    Attributes:
        config_yaml: OpenTelemetry Collector YAML configuration.
        secret_ids: Set of Juju secret URIs referenced in the configuration.
        pipelines: List of enabled pipeline names (metrics, logs, traces).
    """

    config_yaml: str
    pipelines: List[str]

    @field_validator("config_yaml")
    @classmethod
    def validate_yaml(cls, v: str) -> str:
        """Validate that config_yaml is valid YAML and secret URIs have correct format.

        Args:
            v: The config_yaml string to validate.

        Returns:
            The validated config_yaml string.

        Raises:
            ValueError: If the YAML is empty, invalid, or contains malformed secret URIs.
        """
        if not v or not v.strip():
            raise ValueError("config_yaml cannot be empty")
        try:
            yaml.safe_load(v)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")

        # Validate all secret references have the correct format
        secret_refs = _extract_secret_references(v)
        for secret_ref in secret_refs:
            try:
                SecretURI.from_uri(secret_ref)
            except ValueError as e:
                raise ValueError(f"Invalid secret URI '{secret_ref}': {e}")

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
        valid_pipeline_values = {p.value for p in Pipeline}
        invalid = set(v) - valid_pipeline_values
        if invalid:
            raise ValueError(f"Invalid pipelines: {invalid}. Must be one of {valid_pipeline_values}")
        if not v:
            raise ValueError("At least one pipeline must be enabled")
        return v


class OtelcolIntegratorProviderRelationUpdater:
    """Updates relation data for Otelcol integrator provider relations."""

    @staticmethod
    def update_relations_data(
        application: Application,
        relations: List[Relation],
        data: OtelcolIntegratorProviderAppData,
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
            logger.info("Updated relation %d with config and secrets", relation.id)


class OtelcolIntegratorRequirer:
    """Requirer side (e.g. otelcol) of the external-config relation.

    This class is used by charms that consume configuration from
    otelcol-integrator via the external-config relation.
    """

    def __init__(self, model: Model, relation_name: str, secrets_dir: str):
        """Initialize the requirer with the Juju model.

        Args:
            model: The Juju model to use for resolving secrets.
            relation_name: Name of the relation to use.
            secrets_dir: Directory where secret files should be stored.
        """
        self._model = model
        self._relation_name = relation_name

        # Create internal helper instances
        self._file_manager = _SecretFileManager(secrets_dir)
        self._secret_resolver = _SecretResolver(model)

    @property
    def secret_files(self) -> Dict[str, str]:
        """Get mapping of file paths to secret content for file-based secrets."""
        return self._file_manager.tracked_files

    def _validate_and_parse_relation_data(
        self, relation: Relation
    ) -> Optional["OtelcolIntegratorProviderAppData"]:
        """Validate and parse relation data from a single relation.

        Args:
            relation: The relation to validate and parse data from.

        Returns:
            Validated OtelcolIntegratorProviderAppData if successful, None otherwise.
        """
        if not (app_data := relation.data.get(relation.app)):
            return None

        try:
            pipelines_json = app_data.get("pipelines", "[]")
            pipelines = json.loads(pipelines_json)
        except json.JSONDecodeError as e:
            logger.warning("Skipping relation %d: invalid pipelines - %s", relation.id, e)
            return None

        try:
            relation_data = OtelcolIntegratorProviderAppData(
                config_yaml=app_data.get("config_yaml", ""),
                pipelines=pipelines
            )
        except ValueError as e:
            logger.warning("Skipping relation %d: invalid data - %s", relation.id, e)
            return None

        return relation_data

    def _process_relation(self, relation: Relation) -> Optional[Dict[str, Any]]:
        """Process a single relation: validate data and resolve secrets.

        Args:
            relation: The relation to process.

        Returns:
            Dictionary with config_yaml and pipelines if successful, None otherwise.
        """
        if not (relation_data := self._validate_and_parse_relation_data(relation)):
            return None

        try:
            config_yaml = self._secret_resolver.resolve(
                relation_data.config_yaml,
                self._file_manager
            )
        except ValueError as e:
            logger.warning("Skipping relation %d: secret resolution failed - %s", relation.id, e)
            return None

        return {
            "config_yaml": config_yaml,
            "pipelines": relation_data.pipelines
        }

    def retrieve_external_configs(
        self,
    ) -> List[Dict[str, Any]]:
        """Retrieve the config_yaml from the external-config relation.

        Args:
            relations: List of relations to extract configurations from.

        Returns:
            List of dictionaries containing config_yaml and pipelines.
            Secret URIs in config_yaml are replaced with actual values.
            Invalid relation data is skipped with a warning.
        """
        config = []

        if not (relations := self._model.relations.get(self._relation_name, [])):
            logger.debug("No relations found for relation name: %s", self._relation_name)
            return config

        for relation in relations:
            if config_dict := self._process_relation(relation):
                config.append(config_dict)

        return config


# ============================================================================
# PRIVATE HELPERS - Internal implementation details
# ============================================================================

class _SecretFileManager:
    """Manages file paths for secrets and tracks files to be written by the charm.

    This is a private helper class that handles the generation of file paths
    for file-based secrets and keeps track of which files need to be written.
    The actual file writing is delegated to the charm.
    """

    def __init__(self, secrets_dir: str):
        """Initialize the file manager with a secrets directory.

        Args:
            secrets_dir: Base directory where secret files should be stored.
        """
        self._secrets_dir = Path(secrets_dir)
        self._tracked_files = {}

    def generate_path(self, secret_id: str, secret_key: str) -> str:
        """Generate a file path for a secret.

        Args:
            secret_id: The base secret ID (e.g., "secret://model-uuid/secret-id")
            secret_key: The key within the secret.

        Returns:
            The file path where the secret should be written.
        """
        # Extract just the secret-id portion from the full URI
        secret_id_part = urlparse(secret_id).path.strip("/")
        file_name = f"{secret_id_part}_{secret_key}"
        file_path = self._secrets_dir / file_name
        return str(file_path)

    def track_file(self, path: str, content: str) -> None:
        """Track a file that needs to be written by the charm.

        Args:
            path: The file path where the secret should be written.
            content: The secret content to write.
        """
        self._tracked_files[path] = content

    @property
    def tracked_files(self) -> Dict[str, str]:
        """Get the dictionary of tracked files.

        Returns:
            Dictionary mapping file paths to their content.
        """
        return self._tracked_files


class _SecretResolver:
    """Resolves secret URIs in configuration by fetching from Juju.

    This is a private helper class that handles the resolution of secret URIs
    in the configuration YAML, fetching secrets from Juju and replacing URIs
    with actual values or file paths.
    """

    def __init__(self, model: Model):
        """Initialize the secret resolver with a Juju model.

        Args:
            model: The Juju model to use for fetching secrets.
        """
        self._model = model

    def resolve(self, config_yaml: str, file_manager: _SecretFileManager) -> str:
        """Resolve all secret URIs in the configuration.

        Args:
            config_yaml: YAML configuration containing secret URIs.
            file_manager: File manager to use for tracking file-based secrets.

        Returns:
            Configuration with secret URIs replaced by their values or file paths.
        """
        # Step 1: Extract all base secret IDs (without keys)
        base_secret_ids = extract_secret_uris(config_yaml)
        if not base_secret_ids:
            return config_yaml

        # Step 2: Find ALL secret references (including those with keys)
        secret_uri_references = _extract_secret_references(config_yaml)

        # Step 3: Fetch all secrets upfront and cache
        secrets_by_base_id = self._fetch_secrets(base_secret_ids)

        # Step 4: Replace each reference with its corresponding value
        resolved_config_yaml = config_yaml
        for secret_uri_string in secret_uri_references:
            # Parse the secret URI using SecretURI class
            secret_uri = SecretURI.from_uri(secret_uri_string)

            # Reconstruct base secret ID for cache lookup
            base_secret_id = f"secret://{secret_uri.model_uuid}/{secret_uri.secret_id}"

            # Get the value from cache
            secret_content = secrets_by_base_id.get(base_secret_id, {}).get(secret_uri.key)
            if not secret_content:
                raise ValueError(f"Secret key '{secret_uri.key}' not found in secret '{base_secret_id}'")

            # Handle file-based secrets
            replacement_value = secret_content
            if secret_uri.render == 'file':
                # Generate path using the base secret ID and key
                secret_file_path = file_manager.generate_path(base_secret_id, secret_uri.key)
                file_manager.track_file(secret_file_path, secret_content)
                replacement_value = secret_file_path

            resolved_config_yaml = resolved_config_yaml.replace(secret_uri_string, replacement_value)
            logger.debug(
                "Resolved secret URI '%s' to key '%s' in secret %s",
                secret_uri.to_uri(),
                secret_uri.key,
                base_secret_id,
            )

        return resolved_config_yaml

    def _fetch_secrets(self, secret_ids: Set[str]) -> Dict[str, Dict[str, str]]:
        """Fetch secrets from Juju and cache them.

        Args:
            secret_ids: Set of base secret IDs to fetch.

        Returns:
            Dictionary mapping secret IDs to their content dictionaries.
        """
        secrets_cache = {}

        for secret_id in secret_ids:
            try:
                secret = self._model.get_secret(id=secret_id)
                secret_content = secret.get_content(refresh=True)
                secrets_cache[secret_id] = secret_content
                logger.debug("Fetched secret %s with %d keys: %s", secret_id, len(secret_content), list(secret_content.keys()))
            except SecretNotFoundError:
                logger.error("Secret not found: %s", secret_id)
                secrets_cache[secret_id] = {}
            except ModelError as e:
                logger.error("Failed to fetch secret %s: %s", secret_id, e)
                secrets_cache[secret_id] = {}

        return secrets_cache


# ============================================================================
# UTILITY FUNCTIONS - Low-level helpers
# ============================================================================

def extract_secret_uris(config_yaml: str) -> Set[str]:
    """Extract base secret URIs (without keys) from the config YAML.

    Searches for secret URIs in the format: secret://model-uuid/secret-id

    Args:
        config_yaml: YAML configuration text that may contain secret URIs

    Returns:
        Set of unique base secret URIs (secret://model-uuid/secret-id)
    """
    secret_pattern = SECRET_URI_PATTERN_COMP

    if secret_ids := set(secret_pattern.findall(config_yaml)):
        logger.debug("Found %d secret URI(s) in configuration", len(secret_ids))

    return secret_ids


def _extract_secret_references(config_yaml: str) -> Set[str]:
    """Extract all secret references (with keys and query strings) from the config YAML.

    Searches for secret URIs in the format: secret://model-uuid/secret-id[/key][?query]

    Args:
        config_yaml: YAML configuration text that may contain secret references

    Returns:
        Set of unique secret references with keys and query strings
    """
    secret_pattern = SECRET_URI_PATTERN_EXTENDED_COMP
    return set(secret_pattern.findall(config_yaml))
