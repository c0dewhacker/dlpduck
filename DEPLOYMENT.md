# Deployment guide

DLPDuck can run as a Python service, a single Docker container, or a Kubernetes
workload installed with Helm. Persistent storage is required for real use: the
drop folder, archive, quarantine, working index and audit trail all survive
container replacement.

## Kubernetes with Helm

The chart runs the watcher and console together in one pod. It uses one replica
and a `Recreate` strategy because both processes share local state and only one
watcher may claim files from a drop folder.

Create a local administrator password hash:

```bash
docker run --rm c0dewhacker/dlpduck:latest console hash-password
```

Copy `charts/dlpduck/values.yaml` to a private values file. Set the generated
hash under `configuration.data.console.auth.users`, then provide application
secrets. For a quick evaluation Helm can create the Secret:

```yaml
secrets:
  hmacKey: "replace-with-output-of-openssl-rand-hex-32"
  sessionSecret: "replace-with-output-of-openssl-rand-hex-32"

configuration:
  data:
    console:
      bind: 0.0.0.0:8080
      session_secret_env: DLPDUCK_SESSION_SECRET
      session_cookie_secure: false
      auth:
        users:
          - username: admin
            password_hash: "$argon2id$..."
            roles: [dlp_admin]
```

Install and verify the release:

```bash
helm upgrade --install dlpduck charts/dlpduck \
  --namespace dlpduck --create-namespace -f my-values.yaml
kubectl rollout status deployment/dlpduck -n dlpduck
helm test dlpduck -n dlpduck
kubectl port-forward -n dlpduck service/dlpduck 8080:8080
```

Open <http://127.0.0.1:8080>. Place PDFs on the PVC named `dlpduck-drop`, or set
`persistence.drop.existingClaim` to a claim already mounted by your scanner or
file-transfer service.

For production, create secrets outside Helm so they do not appear in Helm
release values:

```bash
kubectl create namespace dlpduck
kubectl create secret generic dlpduck-secrets -n dlpduck \
  --from-literal=DLPDUCK_HMAC_KEY="$(openssl rand -hex 32)" \
  --from-literal=DLPDUCK_SESSION_SECRET="$(openssl rand -hex 32)"
```

Then set:

```yaml
secrets:
  create: false
  existingSecret: dlpduck-secrets
```

Keep the HMAC key stable. Changing it breaks correlation of masked findings
across documents. Rotating the session secret signs users out.

### Environment configuration

Every YAML value can be overridden with a double-underscore environment path.
Environment values are applied before validation and take precedence over the
file:

```text
DLPDUCK__SOURCE__POLL_SECONDS=2
DLPDUCK__CONSOLE__BIND=0.0.0.0:8080
DLPDUCK__CONSOLE__AUTH__OIDC__ISSUER=https://idp.example/realms/dlpduck
DLPDUCK__CONSOLE__AUTH__OIDC__CLIENT_ID=dlpduck
DLPDUCK__CONSOLE__AUTH__OIDC__ROLE_MAP={"compliance-team":"auditor"}
```

Lists and mappings accept JSON or inline YAML. The three secret values are
read directly from `DLPDUCK_HMAC_KEY`, `DLPDUCK_SESSION_SECRET`, and
`DLPDUCK_OIDC_CLIENT_SECRET`.

The chart loads every key from `secrets.existingSecret` into the container. A
Secret managed by External Secrets, Sealed Secrets, SOPS, or another controller
can therefore contain both direct secrets and configuration overrides:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: dlpduck-secrets
  namespace: dlpduck
type: Opaque
stringData:
  DLPDUCK_HMAC_KEY: "..."
  DLPDUCK_SESSION_SECRET: "..."
  DLPDUCK_OIDC_CLIENT_SECRET: "..."
  DLPDUCK__CONSOLE__AUTH__OIDC__ISSUER: "https://idp.example/realms/dlpduck"
  DLPDUCK__CONSOLE__AUTH__OIDC__CLIENT_ID: "dlpduck"
```

Non-secret overrides can instead be set under `configuration.env`. Use
`extraEnv` for individual `secretKeyRef` entries and `extraEnvFrom` for
additional Secret or ConfigMap sources.

### Logging

`logging.level` (default `INFO`) sets `DLPDUCK_LOG_LEVEL`; `DEBUG` is safe to
turn on in production — it traces the pipeline, rule matches and plugin runs,
but never a raw document value:

```yaml
logging:
  level: DEBUG
```

Actual document content — full extracted text, a rule's raw unmasked match —
needs a second, separate opt-in that only takes effect when `level: DEBUG` is
also set:

```yaml
logging:
  level: DEBUG
  traceContentOutput: true
```

Turn this on for a deliberate, temporary debugging session — never leave it
set as a standing default. See the main README's "Logging" section.

### Storage

The chart creates separate claims for:

| Claim | Contents | Operational guidance |
|---|---|---|
| `drop` | Incoming PDFs and metadata | Use an existing claim or RWX storage when another pod or node writes scans. |
| `archive` | Documents that passed policy | Back up according to document retention policy. |
| `quarantine` | Sensitive or incompletely assessed documents | Restrict access independently from the archive. |
| `work` | Searchable content, index, failures and plugin spool | Back up with the archive to preserve console state. |
| `audit` | Hash-chained audit events | Keep durable and access-controlled; verify after restoration. |

Each `persistence.<name>` block accepts `storageClass`, `accessModes`, `size`,
and `existingClaim`. Disabling a claim uses ephemeral `emptyDir` storage and is
appropriate only for temporary evaluation. Generated claims use Helm's `keep`
policy by default, so uninstalling a release leaves its data intact.

### More than one replica

The default — `replicaCount: 1`, strategy `Recreate` — is right for initial
evaluation and for most real deployments; a standalone Docker container and a
plain `dlpduck run` see none of what follows and behave exactly as before.
Raise `replicaCount` only for horizontal scaling or high availability, and
only after both of these are true:

1. **Every `persistence` claim is `ReadWriteMany`, on storage with real POSIX
   file locking** — NFSv4.1 (AWS EFS and GCP Filestore both support this) or
   CephFS. The locking that keeps concurrent writers safe is plain `flock`
   and atomic hardlink-create; a GCS/S3-backed CSI driver or Azure Files
   (SMB) does not implement these reliably and will silently corrupt
   concurrent writes rather than error.
2. **`configuration.data.cluster.leader_election` is set to `"kubernetes"`.**
   Extraction and every console action (retry, purge, resolve, reprocess)
   are already safe under concurrent multi-pod access; the drop-folder watch
   loop is not, and needs exactly one replica running it at a time. Setting
   this switches the deployment strategy to `RollingUpdate` automatically,
   mounts the pod's service account token, and grants it `get`/`create`/
   `update` on one named `Lease` — nothing broader.

```yaml
replicaCount: 3
configuration:
  data:
    cluster:
      leader_election: kubernetes
      # Splits claiming a file (still single-replica, via the lease above)
      # from extracting it, so OCR work is spread across all replicas
      # instead of only ever running on the leader.
      parallel_extraction: true

persistence:
  drop: {accessModes: [ReadWriteMany]}
  archive: {accessModes: [ReadWriteMany]}
  quarantine: {accessModes: [ReadWriteMany]}
  work: {accessModes: [ReadWriteMany]}
  audit: {accessModes: [ReadWriteMany]}
```

Every replica keeps serving the console regardless of which one holds the
lease — only the drop-folder poll loop is gated. See `dlpduck.leader` and
`Pipeline.job_lock` in the source for what actually guards what.

### Ingress and TLS

Enable ingress and secure cookies together:

```yaml
ingress:
  enabled: true
  className: traefik
  host: dlpduck.example.com
  tls:
    enabled: true
    secretName: dlpduck-tls
    certManager:
      enabled: true
      issuerType: ClusterIssuer
      issuerName: letsencrypt-prod

configuration:
  data:
    console:
      bind: 0.0.0.0:8080
      session_secret_env: DLPDUCK_SESSION_SECRET
      session_cookie_secure: true
```

Set `issuerType` to `Issuer` for a namespaced issuer. Limit access at the
ingress, identity provider and network layer; the console contains sensitive
document and audit information.

### Existing configuration and rules

Set `configuration.existingConfigMap` to supply a complete configuration and
additional rule files. The configured key defaults to `config.yaml`. Relative
rule includes resolve from the mounted ConfigMap directory.

All configured paths must match the chart mounts: `/data/drop`, `/data/archive`,
`/data/quarantine`, `/data/work`, and `/data/audit`.

### Upgrades and recovery

Pin `image.tag` when you need explicit control over application upgrades. Review
release notes, take storage snapshots, then run:

```bash
helm upgrade dlpduck charts/dlpduck -n dlpduck -f my-values.yaml
kubectl rollout status deployment/dlpduck -n dlpduck
helm test dlpduck -n dlpduck
```

After restoring or moving the audit claim, verify its chain from the running
pod:

```bash
kubectl exec -n dlpduck deployment/dlpduck -- \
  dlpduck verify-audit --config /etc/dlpduck/config.yaml
```

## Docker

The root README contains a complete single-container example. Mount all five
data paths, set `DLPDUCK_RUN_BOTH=true`, and expose port 8080. The liveness and
readiness endpoints are `/health/live` and `/health/ready`.
