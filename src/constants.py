# Copyright 2026 jose
# See LICENSE file for licensing details.

"""Constants used throughout the charm."""

from enum import Enum

# Relation endpoints
RELATION_ENDPOINT = "external-config"

# Configuration keys
CONFIG_YAML_KEY = "config_yaml"
CONFIG_METRICS_PIPELINE = "metrics_pipeline"
CONFIG_LOGS_PIPELINE = "logs_pipeline"
CONFIG_TRACES_PIPELINE = "traces_pipeline"


class Pipeline(str, Enum):
    """OpenTelemetry Collector pipeline types."""

    METRICS = "metrics"
    LOGS = "logs"
    TRACES = "traces"


# Secret management
SECRET_PARAM_NAME = "name"
SECRET_URI_PATTERN = r'secret://[a-f0-9-]+/[a-z0-9]+'
