# Zarf package: keycloak-portal

Packages the portal for air-gapped / edge delivery. Bundles the container image
and the Helm chart (`../helm/keycloak-portal`) into a single artifact, with
deploy-time config exposed as Zarf variables.

Keycloak and the peat node are **platform prerequisites** — they are not part of
this package.

## Build

```bash
# From the repo root: build/tag the image first (create pulls it from your daemon).
docker build -t keycloak-portal:0.1.29 .
zarf package create deploy/zarf --confirm
# -> zarf-package-keycloak-portal-<arch>-0.1.29.tar.zst
```

For production, push the image to a registry and pin it by digest in
`zarf.yaml` (`images:`), rather than relying on the local daemon.

## Deploy

The target cluster must be initialized (`zarf init`). Then:

```bash
zarf package deploy zarf-package-keycloak-portal-*.tar.zst --confirm \
  --set ISSUER="https://keycloak.example.com/realms/portal" \
  --set HOST="portal.example.com" \
  --set CLIENT_SECRET="<oidc-client-secret>" \
  --set GATEWAY="istio-system/main" \
  --set PEAT_NODE_ADDR="peat-node-peat-node.peat-system.svc:50051"
```

Omitted non-default variables are prompted. The Zarf agent rewrites the bundled
image to the in-cluster registry automatically.

## Variables

| Variable | Default | Notes |
|----------|---------|-------|
| `ISSUER` | — (prompt) | Keycloak realm issuer; identical for browser and pod |
| `CLIENT_ID` | `keycloak-portal` | OIDC client ID |
| `CLIENT_SECRET` | — (prompt, sensitive) | OIDC client secret |
| `HOST` | — (prompt) | Public host; also derives redirect URLs |
| `GATEWAY` | `istio-system/main` | Existing Istio gateway |
| `PEAT_NODE_ADDR` | `peat-node-peat-node.peat-system.svc:50051` | peat node gRPC endpoint |
| `PEAT_TLS` | `false` | Dial peat over TLS |

`zarf-package-*.tar.zst` build artifacts are git-ignored.
