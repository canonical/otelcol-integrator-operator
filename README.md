# OpenTelemetry Collector Integrator Operator

[![CharmHub Badge](https://charmhub.io/otelcol-integrator/badge.svg)](https://charmhub.io/otelcol-integrator)
[![Release](https://github.com/canonical/CHARM-k8s-operator/actions/workflows/release.yaml/badge.svg)](https://github.com/canonical/CHARM-k8s-operator/actions/workflows/release.yaml)
[![Discourse Status](https://img.shields.io/discourse/status?server=https%3A%2F%2Fdiscourse.charmhub.io&style=flat&label=CharmHub%20Discourse)](https://discourse.charmhub.io)

## Description

The OpenTelemetry Collector Integrator Operator is a [Juju](https://juju.is) charm that enables the OpenTelemetry Collector charms to send telemetry data to external non-charmed backends. It acts as a configuration bridge, allowing you to inject arbitrary OpenTelemetry Collector exporter configurations into Opentelemetry Collector instances.

This charm is particularly useful when you need to:
- Export telemetry to **external monitoring backends** (Datadog, New Relic, Splunk, etc.)
- Send metrics, logs, or traces to **SaaS observability platforms**

The charm securely manages Juju secrets containing credentials and API keys, automatically granting access to related OpenTelemetry Collector instances.

## Usage

### Deployment

Deploy the charm to your Juju model:

```bash
juju deploy otelcol-integrator
```

### Creating Secrets

If your configuration includes sensitive data (API keys, tokens, certificates), use the `create-secret` action:

```bash
juju run otelcol-integrator/leader create-secret \
  name=my-secret \
  token=0000-1111-2222-3333 \
  cafile="$(cat service.key | base64 -w0)" \
  certfile="$(cat service.crt | base64 -w0)" \
  keyfile="$(cat service.key | base64 -w0)"
```

> **Important:** File contents must be base64-encoded because the Juju CLI does not preserve newlines in multi-line values. Use `base64 -w0` to encode without line wrapping.

This will output a base secret identifier like:
```
keys: cafile,certfile,keyfile,token
secret-id: secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5odgo7mp25c762tsbv0
```

To use this secret in your configuration, append the key name and render mode to the base secret-id:
- For inline values: `secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5odgo7mp25c762tsbv0/token?render=inline`
- For file-based secrets: `secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5odgo7mp25c762tsbv0/cafile?render=file`

### Configuration

Create a configuration file (e.g., `config.yaml`) with your OpenTelemetry Collector exporter configuration. You can reference secrets using the `secret://` URI format:

```yaml
exporters:
  splunk_hec:
    token: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5odgo7mp25c762tsbv0/token?render=inline"
    endpoint: "https://splunk:8088/services/collector"
    max_idle_conns: 20
    timeout: 100s
    tls:
      insecure_skip_verify: true
      ca_file: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5odgo7mp25c762tsbv0/cafile?render=file"
      cert_file: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5odgo7mp25c762tsbv0/certfile?render=file"
      key_file: "secret://ac2bcddf-4c37-42d4-8ac6-5e7f922c2437/d5odgo7mp25c762tsbv0/keyfile?render=file"
```

**Secret URI format:**
```
secret://<model-uuid>/<secret-id>/<key>?render=<inline|file>
```

Requirements:
- `model-uuid`: Valid UUID v4 format (e.g., `ac2bcddf-4c37-42d4-8ac6-5e7f922c2437`)
- `secret-id`: Exactly 20 lowercase alphanumeric characters (e.g., `d5odgo7mp25c762tsbv0`)
- `key`: The secret key to access (e.g., `token`, `cafile`)
- `render`: How to handle the secret value:
  - `inline`: The secret value is directly substituted in the config
  - `file`: The secret value is written to a file and the file path is substituted

Apply the configuration:

```bash
juju config otelcol-integrator \
  config_yaml=@config.yaml \
  metrics_pipeline=true \
  traces_pipeline=false \
  logs_pipeline=false
```

**Pipeline options:**
- `metrics_pipeline`: Enable the configured exporter to the metrics pipeline (default: false)
- `traces_pipeline`: Enable the configured exporter to the traces pipeline (default: false)
- `logs_pipeline`: Enable the configured exporter to the logs pipeline (default: false)

### Integration

Relate the integrator to an OpenTelemetry Collector charm that supports the `otelcol` relation:

```bash
juju integrate otelcol-integrator:external-config otelcol:external-config
```

The otelcol-integrator will automatically provide the configuration and grant access to any referenced secrets to the related OpenTelemetry Collector instance.

## Example

Complete workflow:

```bash
# Deploy
juju deploy otelcol-integrator
juju deploy otelcol

# Create secret with credentials
juju add-secret splunk-creds \
  token="my-splunk-token" \
  cafile="$(cat splunk-ca.crt  | base64 -w0)"

# Configure
juju config otelcol-integrator \
  config_yaml=@my-exporter-config.yaml \
  metrics_pipeline=true

# Integrate
juju integrate otelcol-integrator:external-config otelcol:external-config
```

# Contributing

Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm, following best practice guidelines, and the [contributing](https://github.com/canonical/CHARM-k8s-operator/blob/main/CONTRIBUTING.md) doc for developer guidance.
```
