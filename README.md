# OpenTelemetry Collector Integrator Operator

## Description

The OpenTelemetry Collector Integrator Operator is a [Juju](https://juju.is) charm that enables the [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) to send telemetry data to external non-charmed backends. It acts as a configuration bridge, allowing you to inject arbitrary OpenTelemetry Collector exporter configurations into Opentelemetry Collector instances.

This charm is particularly useful when you need to:
- Export telemetry to **external monitoring backends** (Datadog, New Relic, Splunk, etc.)
- Send metrics, logs, or traces to **SaaS observability platforms**

The charm securely manages Juju secrets containing credentials and API keys, automatically granting access to related OpenTelemetry Collector instances.
