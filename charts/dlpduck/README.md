# DLPDuck Helm chart

This chart runs the DLPDuck watcher and web console together in one Kubernetes
pod. It provisions separate persistent claims for the watched drop folder,
archive, quarantine, working data and audit trail.

## Install

Create a values file containing your secrets and at least one local user or an
OIDC provider. Generate a local password hash with:

```bash
docker run --rm c0dewhacker/dlpduck:latest console hash-password
```

```yaml
secrets:
  hmacKey: "generated-with-openssl-rand-hex-32"
  sessionSecret: "generated-with-openssl-rand-hex-32"

configuration:
  data:
    console:
      bind: 0.0.0.0:8080
      session_secret_env: DLPDUCK_SESSION_SECRET
      auth:
        users:
          - username: admin
            password_hash: "$argon2id$..."
            roles: [dlp_admin]
```

Because Helm replaces maps recursively but replaces lists and scalar values,
start with `values.yaml` when making a complete application configuration:

```bash
cp charts/dlpduck/values.yaml my-values.yaml
helm upgrade --install dlpduck charts/dlpduck \
  --namespace dlpduck --create-namespace -f my-values.yaml
helm test dlpduck --namespace dlpduck
```

For production, put secrets in a Secret managed outside Helm:

```yaml
secrets:
  create: false
  existingSecret: dlpduck-secrets
```

The Secret must contain `DLPDUCK_HMAC_KEY` and `DLPDUCK_SESSION_SECRET`, plus
any environment variables referenced by OIDC or plugins.

Any application setting can override the generated YAML with a
`DLPDUCK__SECTION__FIELD` environment variable. This lets one external Secret
hold the complete OIDC setup without placing it in the chart ConfigMap:

```yaml
stringData:
  DLPDUCK_HMAC_KEY: "..."
  DLPDUCK_SESSION_SECRET: "..."
  DLPDUCK_OIDC_CLIENT_SECRET: "..."
  DLPDUCK__CONSOLE__AUTH__OIDC__ISSUER: "https://idp.example/realms/dlpduck"
  DLPDUCK__CONSOLE__AUTH__OIDC__CLIENT_ID: "dlpduck"
```

Use `configuration.env` for plain values, `extraEnv` for individual
`secretKeyRef` values, and `extraEnvFrom` for additional Secret sources.

## Logging

```yaml
logging:
  level: DEBUG            # DEBUG | INFO (default) | WARNING | ERROR | CRITICAL
  traceContentOutput: false  # only takes effect when level is also DEBUG
```

`DEBUG` is safe to run in production. `traceContentOutput` logs actual
document content (full extracted text, raw unmasked rule matches) and
requires `level: DEBUG` to also be set — either alone does nothing. Turn it
on for a deliberate debugging session, not as a standing default.

## Storage

The five entries under `persistence` accept a storage class, access modes, size,
or an existing claim. A scanner or upload service that mounts the drop claim
from another node normally needs `ReadWriteMany` storage. Keep quarantine and
audit on dedicated claims with access controls and backup policies appropriate
for sensitive records.

Generated claims carry Helm's `keep` policy by default, so uninstalling the
release does not delete document or audit data. Set `persistence.retain: false`
only when lifecycle management outside the release guarantees the data is safe.

DLPDuck runs one replica with a `Recreate` update strategy by default. Two
watchers must not independently poll the same drop folder — see "More than
one replica" below before raising `replicaCount`.

See the repository [deployment guide](../../DEPLOYMENT.md) for ingress, TLS,
storage, scaling and upgrade examples.

The ingress integration supports cert-manager through either a cluster-wide
`ClusterIssuer` or a namespaced `Issuer`. When TLS is enabled, also set
`configuration.data.console.session_cookie_secure: true`.
