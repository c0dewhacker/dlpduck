# DLPDuck Helm chart

This chart runs the DLPDuck watcher and web console together in one Kubernetes
pod. It provisions separate persistent claims for the watched drop folder,
archive, quarantine, working data and audit trail.

## Install

Create a values file containing your secrets and at least one local user or an
OIDC provider. Generate a local password hash with:

```bash
docker run --rm c0dewhacker/dlpduck:0.1.3 console hash-password
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

## Storage

The five entries under `persistence` accept a storage class, access modes, size,
or an existing claim. A scanner or upload service that mounts the drop claim
from another node normally needs `ReadWriteMany` storage. Keep quarantine and
audit on dedicated claims with access controls and backup policies appropriate
for sensitive records.

Generated claims carry Helm's `keep` policy by default, so uninstalling the
release does not delete document or audit data. Set `persistence.retain: false`
only when lifecycle management outside the release guarantees the data is safe.

DLPDuck intentionally runs one replica with a `Recreate` update strategy. Two
watchers must not consume the same drop folder concurrently.

See the repository [deployment guide](../../DEPLOYMENT.md) for ingress, TLS,
storage and upgrade examples.
