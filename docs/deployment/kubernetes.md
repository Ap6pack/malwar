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
docker build -t ghcr.io/ap6pack/malwar:0.3.0 .
docker push ghcr.io/ap6pack/malwar:0.3.0
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
kubectl get pods -l app.kubernetes.io/name=malwar
kubectl logs -l app.kubernetes.io/name=malwar -f
kubectl port-forward svc/malwar 8000:8000
curl http://127.0.0.1:8000/api/v1/health
```

### Uninstall

```bash
helm uninstall malwar
```

!!! warning
    The PersistentVolumeClaim is not deleted on uninstall to protect data. Delete it manually if needed: `kubectl delete pvc malwar`

---

## Configuration Reference

All configuration is managed through `values.yaml`. Override values with `--set` flags or a custom values file (`-f custom-values.yaml`).

### Image

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/ap6pack/malwar` | Container image repository |
| `image.tag` | `latest` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |

### Replicas and Autoscaling

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | Number of pod replicas |
| `autoscaling.enabled` | `false` | Enable HorizontalPodAutoscaler |
| `autoscaling.minReplicas` | `1` | Minimum replicas |
| `autoscaling.maxReplicas` | `5` | Maximum replicas |

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
| `persistence.size` | `1Gi` | PVC size |

### Malwar Application

| Key | Default | Description |
|-----|---------|-------------|
| `malwar.apiKeys` | `[]` | API authentication keys |
| `malwar.logLevel` | `"INFO"` | Log level |
| `malwar.autoMigrate` | `true` | Auto-run DB migrations on startup |
| `malwar.anthropicApiKey` | `""` | Anthropic API key for LLM layer |
| `malwar.webhookUrls` | `[]` | Webhook notification URLs |
| `malwar.dbPath` | `"/data/malwar.db"` | Database path inside container |

### Security

| Key | Default | Description |
|-----|---------|-------------|
| `securityContext.runAsNonRoot` | `true` | Run as non-root |
| `securityContext.runAsUser` | `1000` | Container user ID |
| `securityContext.readOnlyRootFilesystem` | `true` | Read-only root filesystem |
| `securityContext.allowPrivilegeEscalation` | `false` | Block privilege escalation |

---

## Production Recommendations

### Ingress with TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
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

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

### Secret Management

For production, consider using an external secret manager:

- **Kubernetes External Secrets Operator** -- Sync from AWS Secrets Manager, Vault, etc.
- **Sealed Secrets** -- Encrypt secrets for safe storage in Git.
- **HashiCorp Vault** with the Vault Agent Injector.

---

## Persistence Considerations

### SQLite Limitations

1. **Single writer:** SQLite serializes writes. Multiple replicas may experience write contention.
2. **File-based storage:** Requires a PVC with `ReadWriteOnce` access mode.
3. **No network access:** All replicas must mount the same PVC.

### Recommendations

- **Single replica** is the simplest and most reliable configuration.
- **Back up regularly** using the SQLite `.backup` command.
- **Monitor disk usage** to ensure the PVC has sufficient space.

---

## Monitoring and Health Checks

| Probe | Endpoint | Purpose |
|-------|----------|---------|
| Liveness | `GET /api/v1/health` | Confirms the process is running |
| Readiness | `GET /api/v1/ready` | Confirms the database is connected |

---

## Upgrading

```bash
helm upgrade malwar deploy/helm/malwar/ -f custom-values.yaml
helm upgrade malwar deploy/helm/malwar/ --set image.tag=0.3.0
helm rollback malwar
```

Database migrations run automatically on startup when `malwar.autoMigrate` is `true` (the default).
