# keycloak-portal Helm chart

Deploys the Keycloak OIDC portal to Kubernetes. Built for an **Istio** mesh:
traffic is routed through an **existing Istio Gateway** via a `VirtualService`,
and the pod requests an Istio sidecar (relying on mesh-wide mTLS — no extra
`PeerAuthentication` is rendered).

## Resources rendered

- `Deployment` (nonroot, read-only rootfs, dropped caps) + `Service` (ClusterIP)
- `ConfigMap` (non-sensitive env) + `Secret` (OIDC client secret, optional)
- `ServiceAccount`
- `VirtualService` bound to an existing Gateway (toggleable)
- `HorizontalPodAutoscaler` (optional)

## Prerequisites

- An Istio mesh with an ingress `Gateway` you can bind to (default
  `istio-system/main`).
- A running Keycloak with a confidential client. The client's **Valid redirect
  URI** must equal `config.redirectUrl`.
- The container image available to the cluster (see below).

## Make the image available

The chart defaults to `keycloak-portal:local` with `pullPolicy: IfNotPresent`,
so side-load the locally built image into your cluster (no registry needed):

```bash
docker build -t keycloak-portal:local .          # from repo root

# Pick the one matching your cluster:
kind load docker-image keycloak-portal:local                       # kind
minikube image load keycloak-portal:local                          # minikube
k3d image import keycloak-portal:local -c <cluster-name>           # k3d
# Docker Desktop's k8s shares the local image store — nothing to load.
```

To pull from a registry instead, set `image.repository`/`image.tag` to the
pushed reference and `image.pullPolicy: Always`.

## Install

```bash
helm upgrade --install portal deploy/helm/keycloak-portal \
  -n portal --create-namespace \
  -f deploy/helm/keycloak-portal/values-local.yaml
```

Ensure the target namespace has Istio injection enabled:

```bash
kubectl label namespace portal istio-injection=enabled --overwrite
```

## Key values

| Value | Default | Description |
|-------|---------|-------------|
| `image.repository` / `image.tag` | `keycloak-portal` / `local` | Container image |
| `config.issuer` | `https://keycloak.example.com/realms/portal` | Keycloak realm issuer — must match for browser **and** pod |
| `config.clientId` | `keycloak-portal` | OIDC client ID |
| `config.redirectUrl` | `https://portal.example.com/auth/callback` | Must match a Valid Redirect URI in Keycloak |
| `config.cookieSecure` | `true` | Set `false` only for plain HTTP |
| `clientSecret.value` | `""` | Client secret; chart creates a Secret from it |
| `clientSecret.existingSecret.name` | `""` | Reference an existing Secret instead (then `value` is ignored) |
| `clientSecret.existingSecret.key` | `OIDC_CLIENT_SECRET` | Key within the existing Secret |
| `istio.sidecarInject` | `true` | Add `sidecar.istio.io/inject` to the pod |
| `istio.virtualService.enabled` | `true` | Render the VirtualService |
| `istio.virtualService.gateway` | `istio-system/main` | Existing Gateway to bind to |
| `istio.virtualService.hosts` | `[portal.example.com]` | Hosts served by the route |
| `autoscaling.enabled` | `false` | Enable the HPA |

## Client secret: two modes

**Chart-managed** (simple, local dev):

```yaml
clientSecret:
  value: "my-client-secret"
```

**Existing Secret** (nothing sensitive in values):

```bash
kubectl -n portal create secret generic keycloak-portal-oidc \
  --from-literal=OIDC_CLIENT_SECRET='my-client-secret'
```

```yaml
clientSecret:
  existingSecret:
    name: keycloak-portal-oidc
    key: OIDC_CLIENT_SECRET
```

## The issuer-consistency rule

OIDC token validation checks that the token's `issuer` claim matches the issuer
the app discovered. So `config.issuer` must resolve to the **same** URL from the
browser and from inside the pod. With Istio that is normally Keycloak's public
gateway host (e.g. `https://keycloak.example.com/realms/portal`) — use it for
both, rather than an in-cluster `*.svc.cluster.local` address that the browser
can't reach.

## Uninstall

```bash
helm uninstall portal -n portal
```
