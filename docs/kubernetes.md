<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Kubernetes Deployment Guide

This guide covers deploying Malwar on Kubernetes using the included Helm chart.

---

## Prerequisites

- **Kubernetes** 1.26+ cluster
- **Helm** 3.12+
- **kubectl** configured for your cluster
- A **container registry** with the Malwar image (e.g., `ghcr.io/ap6pack/malwar`)

### Building and Pushing the Image

```bash
# Build the Docker image
docker build -t ghcr.io/ap6pack/malwar:0.2.0 .

# Push to your registry
docker push ghcr.io/ap6pack/malwar:0.2.0
```

---

## Quick Start

### Install with Helm

```bash
# Install with default values
helm install malwar deploy/helm/malwar/

# Install with API keys and Anthropic key
helm install malwar deploy/helm/malwar/ \
  --set malwar.apiKeys[0]=your-secret-api-key \
  --set malwar.anthropicApiKey=sk-ant-your-key-here

# Install into a specific namespace
helm install malwar deploy/helm/malwar/ \
  --namespace malwar \
  --create-namespace
```

### Verify the Deployment

```bash
# Check pod status
kubectl get pods -l app.kubernetes.io/name=malwar

# View logs
kubectl logs -l app.kubernetes.io/name=malwar -f

# Port-forward to access locally
kubectl port-forward svc/malwar 8000:8000

# Test health endpoint
curl http://127.0.0.1:8000/api/v1/health
```

### Uninstall

```bash
helm uninstall malwar
```

> **Note:** The PersistentVolumeClaim is not deleted on uninstall to protect data. Delete it manually if needed:
> `kubectl delete pvc malwar`

---

## Configuration Reference

All configuration is managed through `values.yaml`. Override values with `--set` flags or a custom values file (`-f custom-values.yaml`).

### Image

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/ap6pack/malwar` | Container image repository |
| `image.tag` | `latest` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |
| `imagePullSecrets` | `[]` | Docker registry secrets |

### Replicas and Autoscaling

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | Number of pod replicas |
| `autoscaling.enabled` | `false` | Enable HorizontalPodAutoscaler |
| `autoscaling.minReplicas` | `1` | Minimum replicas |
| `autoscaling.maxReplicas` | `5` | Maximum replicas |
| `autoscaling.targetCPUUtilizationPercentage` | `80` | Target CPU utilization |
| `autoscaling.targetMemoryUtilizationPercentage` | `80` | Target memory utilization |

### Service

| Key | Default | Description |
|-----|---------|-------------|
| `service.type` | `ClusterIP` | Kubernetes service type |
| `service.port` | `8000` | Service port |

### Ingress

| Key | Default | Description |
|-----|---------|-------------|
| `ingress.enabled` | `false` | Enable ingress resource |
| `ingress.className` | `nginx` | Ingress class name |
| `ingress.annotations` | `{}` | Ingress annotations |
| `ingress.hosts` | See values.yaml | Ingress host rules |
| `ingress.tls` | `[]` | TLS configuration |

### Resources

| Key | Default | Description |
|-----|---------|-------------|
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `256Mi` | Memory request |
| `resources.limits.cpu` | `500m` | CPU limit |
| `resources.limits.memory` | `512Mi` | Memory limit |

### Persistence

| Key | Default | Description |
|-----|---------|-------------|
| `persistence.enabled` | `true` | Enable PVC for SQLite data |
| `persistence.storageClass` | `""` | StorageClass (empty = default) |
| `persistence.accessModes` | `[ReadWriteOnce]` | PVC access modes |
| `persistence.size` | `1Gi` | PVC size |

### Malwar Application

| Key | Default | Description |
|-----|---------|-------------|
| `malwar.apiKeys` | `[]` | API authentication keys |
| `malwar.logLevel` | `"INFO"` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `malwar.autoMigrate` | `true` | Auto-run DB migrations on startup |
| `malwar.anthropicApiKey` | `""` | Anthropic API key for LLM layer |
| `malwar.webhookUrls` | `[]` | Webhook notification URLs |
| `malwar.webhookSecret` | `""` | Webhook signing secret |
| `malwar.dbPath` | `"/data/malwar.db"` | Database path inside container |

### Security

| Key | Default | Description |
|-----|---------|-------------|
| `serviceAccount.create` | `true` | Create a ServiceAccount |
| `serviceAccount.annotations` | `{}` | ServiceAccount annotations |
| `serviceAccount.name` | `""` | Override ServiceAccount name |
| `podSecurityContext.fsGroup` | `1000` | Pod filesystem group |
| `securityContext.runAsNonRoot` | `true` | Run as non-root |
| `securityContext.runAsUser` | `1000` | Container user ID |
| `securityContext.readOnlyRootFilesystem` | `true` | Read-only root filesystem |
| `securityContext.allowPrivilegeEscalation` | `false` | Block privilege escalation |

---

## Production Recommendations

### Replicas and Resources

For production workloads, increase replicas and resource limits:

```yaml
replicaCount: 3

resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1Gi
```

> **Important:** SQLite does not support concurrent writes from multiple processes. When running multiple replicas, only one replica at a time can write to the database. See [Persistence Considerations](#persistence-considerations) for guidance.

### Ingress with TLS

Enable ingress with TLS using cert-manager:

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
  hosts:
    - host: malwar.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: malwar-tls
      hosts:
        - malwar.example.com
```

### Autoscaling

Enable horizontal pod autoscaling for variable workloads:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

### Secret Management

For production, consider using an external secret manager instead of storing secrets in Helm values:

- **Kubernetes External Secrets Operator** -- Sync secrets from AWS Secrets Manager, HashiCorp Vault, etc.
- **Sealed Secrets** -- Encrypt secrets for safe storage in Git.
- **HashiCorp Vault** with the Vault Agent Injector.

---

## Persistence Considerations

### SQLite Limitations

Malwar uses SQLite as its database backend. This has important implications for Kubernetes deployments:

1. **Single writer:** SQLite supports concurrent reads but serializes writes. Running multiple replicas against the same PVC works for read-heavy workloads but may experience write contention.

2. **File-based storage:** The database is a single file on disk. It requires a PersistentVolumeClaim with `ReadWriteOnce` access mode.

3. **No network access:** SQLite does not support network-based access. All replicas must mount the same PVC, which limits scaling to nodes that can access the same volume.

### Recommendations

- **Single replica** is the simplest and most reliable configuration for SQLite.
- **Back up regularly** using the SQLite `.backup` command or by copying the database file.
- **Monitor disk usage** to ensure the PVC has sufficient space.

### Migration Path to PostgreSQL

For high-availability or multi-replica deployments, consider migrating to PostgreSQL:

1. Deploy PostgreSQL using the Bitnami Helm chart or a managed service (RDS, Cloud SQL).
2. Update the Malwar configuration to use `MALWAR_DB_URL` with a PostgreSQL connection string.
3. Run the database migration tool to transfer existing data.
4. Remove the PVC and set `persistence.enabled: false`.

---

## Monitoring and Health Checks

### Health Endpoints

The Helm chart configures two probes:

| Probe | Endpoint | Purpose |
|-------|----------|---------|
| Liveness | `GET /api/v1/health` | Confirms the process is running. Failure triggers pod restart. |
| Readiness | `GET /api/v1/ready` | Confirms the database is connected. Failure removes pod from service endpoints. |

### Probe Configuration

The default probe settings are:

- **Liveness:** initial delay 10s, period 30s, timeout 5s, failure threshold 3
- **Readiness:** initial delay 5s, period 10s, timeout 5s, failure threshold 3

### Log Aggregation

Malwar outputs structured JSON logs by default. Configure your cluster's log aggregation (Fluentd, Fluent Bit, Loki) to collect logs from Malwar pods.

Set the log level via:

```yaml
malwar:
  logLevel: "INFO"  # DEBUG, INFO, WARNING, ERROR
```

### Metrics

For Prometheus monitoring, consider adding a sidecar or middleware that exposes `/metrics`. The health endpoints can also be used as Prometheus blackbox exporter targets.

---

## Upgrading

### Helm Upgrade

```bash
# Upgrade to a new chart version
helm upgrade malwar deploy/helm/malwar/ -f custom-values.yaml

# Upgrade the image tag
helm upgrade malwar deploy/helm/malwar/ --set image.tag=0.3.0

# Roll back if needed
helm rollback malwar
```

### Database Migrations

When `malwar.autoMigrate` is `true` (the default), database migrations run automatically on startup. The migration system is idempotent -- running migrations multiple times is safe.

For manual migration control:

```yaml
malwar:
  autoMigrate: false
```

Then run migrations manually before upgrading:

```bash
kubectl exec -it deploy/malwar -- python -m malwar db migrate
```

### Zero-Downtime Upgrades

The deployment uses a rolling update strategy by default. The readiness probe ensures that new pods are fully initialized before receiving traffic. To maintain availability during upgrades:

1. Run at least 2 replicas.
2. Set appropriate `maxUnavailable` and `maxSurge` in the deployment strategy.
3. Ensure database migrations are backward-compatible.
