# M-WAF Agent protocol v1

## Connection model

Manager exposes the administrator UI and Agent API through one HTTPS listener. The default address is `:8443` and `MWAF_PUBLIC_URL` is the externally reachable base URL. There is no separate Agent port.

Agent never accepts an inbound management connection. At the configured heartbeat interval, 30 seconds by default, Agent initiates a control cycle to Manager:

1. send inventory, health, current policy, spool status, and last command ID;
2. fetch desired policy and package state;
3. download and apply only signed artifacts whose desired state changed;
4. poll one fixed allowlisted control command;
5. report policy, package, and command results.

Audit events are uploaded by a separate Agent-initiated batch loop. Manager does not use WebSocket, server push, reverse callbacks, or an Agent listening socket.

Heartbeat inventory reports optional capability fields including `cpu_core_count`, `memory_total_bytes`, `installation_mode`, Connector version/load state, configtest status, supported policy artifact formats, and the `capabilities` list. Agent `0.2.0` reports `agent-self-update-v1` and `agent-local-rollback-v1`; Manager creates Agent-only desired state only when both are present. Older Agents may omit the fields and continue on the legacy package-managed path, or use the authenticated one-time upgrade endpoint through the verified installer.

## Authoritative contract

The machine-readable protocol contract is defined in `internal/protocol/agent_v1.go`. It contains:

- version, direction, transport, default poll interval, authentication modes, and size limits;
- method, path, authentication, request type, and response type for every Agent endpoint;
- path builders shared by the Agent client and Manager router;
- wire payload aliases for the JSON structures in `internal/model`.

Route constants must be changed in that package first. Client and Manager code must not introduce literal Agent API paths.

## Authentication

The quick command downloads the installer with `wget --no-check-certificate` and immediately verifies its SHA-256 against the value copied from the authenticated Manager UI. The verified installer then uses the copied SPKI pin with curl `--insecure --pinnedpubkey` only to download the public M-WAF CA. All enrollment, package, and Agent traffic uses the downloaded CA through normal certificate verification. Operators that pre-provision the CA can continue to pass `--ca` directly.

| Phase | Authentication | Result |
|---|---|---|
| Installer bootstrap | Installer SHA-256 from authenticated UI | Exact downloaded installer bytes verified before execution |
| Bootstrap trust | Manager TLS SPKI pin | Verified download of the public M-WAF CA |
| Bootstrap | Enterprise install token over server-authenticated TLS | Short-lived, one-use enrollment session |
| Enrollment | Enrollment token plus Agent-generated CSR | Per-Agent certificate and CA chain |
| Normal operation | mTLS certificate whose identity maps to one active server | Enterprise-scoped heartbeat, policy, package, and command access |
| Detection log receive | Agent mTLS certificate plus `X-MWAF-Event-Token` | Event batch accepted only when both values resolve to the same enterprise |
| Certificate renewal | Current valid Agent mTLS certificate plus a new CSR | Rotated Agent certificate |

The shared TLS listener accepts a client certificate when supplied. Every authenticated `/agent/v1/*` route independently requires and validates the Agent identity; administrator browser routes do not require a client certificate. Only `/agent/v1/events/batch` additionally accepts `X-MWAF-Event-Token`, and no other Agent endpoint uses that token.

## Stable Agent endpoints

| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/bootstrap/v1/ca.crt` | none | Public M-WAF CA certificate |
| POST | `/agent/v1/enroll` | `EnrollRequest` | `EnrollResponse` |
| POST | `/agent/v1/heartbeat` | `HeartbeatRequest` | empty success |
| POST | `/agent/v1/certificate/renew` | `CertificateRenewRequest` | `CertificateRenewResponse` |
| GET | `/agent/v1/desired-state` | none | `DesiredState` |
| GET | `/agent/v1/policy-key` | none | Ed25519 public key PEM |
| GET | `/agent/v1/artifacts/{id}` | none | signed policy artifact |
| GET | `/agent/v1/base-artifacts/{id}` | none | signed immutable base-policy artifact assigned to the Agent |
| GET | `/agent/v1/packages/{id}` | none | signed package artifact |
| POST | `/agent/v1/upgrades` | none | latest compatible Agent deployment for the existing mTLS identity |
| POST | `/agent/v1/upgrades/complete` | Agent version | confirm the one-time legacy transition after the new-version heartbeat is visible |
| POST | `/agent/v1/events/batch` | `EventBatch` | empty success |
| POST | `/agent/v1/policies/{id}/result` | `DeploymentResult` | empty success |
| POST | `/agent/v1/package-deployments/{id}/result` | `DeploymentResult` | empty success |
| GET | `/agent/v1/commands/next` | none | one allowlisted `AgentCommand` or no-content |
| POST | `/agent/v1/commands/{id}/result` | `DeploymentResult` | empty success |

Bootstrap installer, package resolution, and package-key paths are in the same protocol package. Policy artifacts are limited to 64 MiB, package artifacts to 1 GiB, and one event batch to 500 events. The event verification header is an authentication hardening change and requires a coordinated Manager and Agent configuration rollout; deploying the Manager first will reject event batches from Agents that do not yet have the protected token file.

For Agent-only updates, `PackageDeployment.scope` is `agent`, `agent` contains the target DEB, and `rollback_agent` may contain the previous verified DEB. The `module` field is omitted and the Agent does not touch module, policy, or web-server configuration state. A missing scope keeps the existing `agent_module` behavior for older peers.

For new structured enterprise revisions, `DesiredState` includes `base_policy` and `override_policy`. Manager first validates that the immutable system base plus the enterprise-only override reproduces the effective configuration, then signs both artifacts and pins the base hash, override configuration hash, effective configuration hash, and validation digest in the override manifest. Agent downloads both artifacts from the Manager, verifies both signatures and hashes, verifies the pinned composition fields, merges only their allowlisted files, and runs the existing web-server configtest before the atomic switch. Existing `conf-v1`, `policy-bundle-v2`, and `policy-bundle-v3` desired states remain readable through the legacy single-artifact fields.

## Compatibility rule

The current path family remains `v1`. Adding optional JSON fields is permitted when older peers ignore them. Removing or changing a field, authentication rule, method, or path requires a new protocol version and a compatibility period. The mandatory event verification header is explicitly tracked as a coordinated pre-stable MVP rollout and must not be deployed as a Manager-only change.
