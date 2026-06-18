# Full stack UDS bundle (init + Core + portal)

A single, transportable bundle that stands up the **whole platform from nothing**:

1. **UDS init** (`v0.39.0`) — in-cluster registry + Zarf agent.
2. **UDS Core, slim-dev** (`0.40.0`) — Istio + Keycloak (SSO) + Pepr/UDS Operator.
3. **keycloak-portal** (`0.1.29`) — the app (built from `../zarf`).

Packages deploy in that order. Use this for a fresh cluster (e.g. local k3s) or
air-gap transport. If init + Core are **already** on the cluster, use the
app-only bundle in [`../uds`](../uds) instead.

> You still need a peat node on the cluster — it's a platform prerequisite, not
> part of this bundle. Point the app at it with `--set PEAT_NODE_ADDR=...`.

## Build

Build the app image first (the Zarf package bundles it), then create the bundle.
Bundles are architecture-specific.

```bash
# from this directory (deploy/uds-full)
docker build -t keycloak-portal:0.1.29 ../..
uds create . --architecture amd64 --confirm      # or --architecture arm64
```

This produces `uds-bundle-keycloak-portal-stack-<arch>-0.1.29.tar.zst` — the
single file you transport.

## Deploy

```bash
uds deploy uds-bundle-keycloak-portal-stack-*.tar.zst --confirm \
  --set DOMAIN=uds.dev \
  --set PORTAL_HOST=portal \
  --set PEAT_NODE_ADDR=peat-node-peat-node.peat-system.svc:50051
```

- `--set DOMAIN=...` applies to **both** Core and the app (they share the
  variable name), so their hostnames/OIDC URLs line up. Default `uds.dev`.
- The portal lands at `https://<PORTAL_HOST>.<DOMAIN>` (e.g. `https://portal.uds.dev`).
- Point `*.<DOMAIN>` at the Istio tenant gateway's external IP (MetalLB IP, or
  `/etc/hosts` for a quick local test).

## Notes

- **Versions are pinned** here (init `v0.39.0`, Core `0.40.0`, app `0.1.29`). Bump
  the `ref`s in `uds-bundle.yaml` to move them together.
- For a **fully air-gapped** site, also set `--set API_EGRESS=false` and point
  `--set WEATHER_API_URL=` at an in-cluster mirror (see the app's config).
- `uds create` pulls the remote init/Core images at build time, so run it
  somewhere with registry access; the resulting `.tar.zst` is self-contained.
