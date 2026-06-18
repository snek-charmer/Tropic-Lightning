# Keycloak Portal

A Go web portal that authenticates users via **Keycloak** using OpenID Connect
(authorization code flow) and enforces **role-based access** using the roles
defined in Keycloak. It serves server-rendered pages for browsers and exposes a
JSON API for programmatic, bearer-token callers — both validated through the
same path.

## How it works

1. The user clicks **Sign in with Keycloak** → redirected to Keycloak with a
   CSRF `state` and a `nonce`.
2. Keycloak authenticates the user and redirects back to `/auth/callback`.
3. The app exchanges the code for tokens, verifies the ID token + nonce, and
   stores the access token in a secure session cookie.
4. On every protected request, middleware verifies the access token (JWT
   signature, issuer, expiry) and extracts roles from Keycloak's
   `realm_access.roles` and `resource_access.<client>.roles` claims.
5. Route guards (`RequireRealmRole`, `RequireClientRole`) gate access by role.

The access token is read from the `Authorization: Bearer <token>` header if
present (API clients), otherwise from the session cookie (browser navigation).

## Routes

| Method | Path             | Access                               |
|--------|------------------|--------------------------------------|
| GET    | `/`              | public (landing page)                |
| GET    | `/auth/login`    | public (starts OIDC flow)            |
| GET    | `/auth/callback` | public (OIDC redirect target)        |
| POST   | `/auth/logout`   | public (clears session + SSO logout) |
| GET    | `/dashboard`     | any authenticated user               |
| GET    | `/api/me`        | any authenticated user (JSON claims) |
| GET    | `/api/admin`     | admin (realm role `admin` or admin group) |
| GET    | `/datasources`   | admin (realm role or admin group), HTML |
| POST   | `/datasources`   | `admin` (HTML form create)           |
| POST   | `/datasources/{id}/delete` | `admin` (HTML form delete) |
| GET    | `/api/datasources` | `admin` (JSON list)                |
| POST   | `/api/datasources` | `admin` (JSON create)              |
| DELETE | `/api/datasources/{id}` | `admin` (JSON delete)         |

## Data sources (edge / disconnected)

Admins can register **data sources** — external system connections (Postgres,
S3, HTTP, MQTT, …) described by name, type, endpoint, optional `secret_ref`, and
an enabled flag. This is built for an **edge node that operates disconnected and
syncs back when it reconnects** — and the storage layer is what makes that work:

- **peat node is the backend.** Records are stored in a local
  [peat](https://github.com/defenseunicorns/peat) node — a CRDT mesh datastore —
  as JSON documents in a collection (`data_sources`), via the `PeatSidecar`
  gRPC API (`PutDocument`/`GetDocument`/`ListDocuments`/`DeleteDocument`).
- **Offline-first is peat's job, not ours.** The node persists locally and keeps
  serving reads/writes while disconnected; it reconciles state across the mesh
  with Automerge CRDTs (conflict-free, no central server) once peers are
  reachable. The app holds no separate database and runs no sync worker.
- **Mesh status, not per-record state.** The UI shows the node's live status
  from `GetStatus` (connected peers / syncing vs operating disconnected) rather
  than a hand-rolled per-record sync flag.
- **Clean seam.** Storage is behind a `Store` interface; the peat-backed
  implementation lives in `internal/datasource/peatstore.go`, with an in-memory
  `Store` used for tests.

> Credentials are never stored in the app — `secret_ref` points at where they
> live (a Kubernetes Secret name, vault path, etc.).

The gRPC contract is vendored at `proto/peat/sidecar/v1/sidecar.proto` and the
Go client is generated into `internal/peat/sidecarv1/` (see `proto/README.md`).
peat is pre-1.0, so re-vendor + regenerate when bumping the node version.

## Configuration

Copy `.env.example` and set the values, then export them (or use a tool like
`direnv` / `dotenv`):

```bash
cp .env.example .env
set -a && source .env && set +a
```

| Variable                        | Required | Description                                   |
|---------------------------------|----------|-----------------------------------------------|
| `KEYCLOAK_ISSUER`               | yes      | `https://host/realms/<realm>`                 |
| `OIDC_CLIENT_ID`                | yes      | Keycloak client ID                            |
| `OIDC_CLIENT_SECRET`            | yes      | Keycloak client secret (confidential client)  |
| `OIDC_REDIRECT_URL`             | no       | Must match a Valid Redirect URI in Keycloak   |
| `OIDC_POST_LOGOUT_REDIRECT_URL` | no       | Where to land after logout                    |
| `OIDC_SCOPES`                   | no       | Default `openid profile email roles`          |
| `LISTEN_ADDR`                   | no       | Default `:3000`                               |
| `COOKIE_SECURE`                 | no       | Set `true` behind HTTPS in production         |
| `ADMIN_GROUP`                   | no       | Keycloak group granting admin (default `/UDS Core/Admin`) |
| `PEAT_NODE_ADDR`                | yes      | peat node gRPC endpoint (e.g. `localhost:50051`) |
| `PEAT_COLLECTION`               | no       | peat document collection (default `data_sources`) |
| `PEAT_TLS`                      | no       | Dial the peat node over TLS (default `false`) |

## Run

```bash
go run ./cmd/portal
# or
go build -o bin/portal ./cmd/portal && ./bin/portal
```

Open http://localhost:3000.

## Run locally with Docker (recommended for testing)

`docker-compose.yml` brings up the portal **and** a Keycloak that auto-imports a
realm, a confidential client, realm roles, and two test users — so you can log
in end-to-end with zero manual Keycloak configuration.

**One-time host setup.** The OIDC issuer must be identical for your browser and
the portal container, so both must reach Keycloak at the same hostname. Add this
to `/etc/hosts`:

```
127.0.0.1   keycloak
```

Then:

```bash
docker compose up --build
```

| What            | URL / credentials                                   |
|-----------------|-----------------------------------------------------|
| Portal          | http://localhost:3000                               |
| Keycloak admin  | http://keycloak:8080 — `admin` / `admin`            |
| Test user       | `alice` / `password` — has the **admin** realm role |
| Test user       | `bob` / `password` — has the **user** realm role    |

Sign in as `alice` to see the admin role on the dashboard and access
`/api/admin`; sign in as `bob` to see `/api/admin` return 403.

> The portal has `restart: unless-stopped`; on first boot it may restart once or
> twice (logging a discovery error) while Keycloak finishes starting, then
> connects. The `depends_on` healthcheck normally prevents this.

To build just the image (no Keycloak):

```bash
docker build -t keycloak-portal:local .
docker run --rm -p 3000:3000 --env-file .env keycloak-portal:local
```

## Deploy to Kubernetes (Istio)

A Helm chart lives in [`deploy/helm/keycloak-portal`](deploy/helm/keycloak-portal).
It targets an Istio mesh: it routes through an existing Istio `Gateway` via a
`VirtualService` and requests an Istio sidecar on the pod. The OIDC client secret
can be chart-managed or sourced from an existing `Secret`.

```bash
docker build -t keycloak-portal:local .
kind load docker-image keycloak-portal:local      # or minikube/k3d equivalent

helm upgrade --install portal deploy/helm/keycloak-portal \
  -n portal --create-namespace \
  -f deploy/helm/keycloak-portal/values-local.yaml
```

See the [chart README](deploy/helm/keycloak-portal/README.md) for values,
image-loading per cluster type, and the issuer-consistency rule.

## Deploy as a Zarf package (air-gapped / edge)

For disconnected delivery, the app ships as a [Zarf](https://zarf.dev) package in
[`deploy/zarf`](deploy/zarf). It bundles the container image **and** the Helm
chart into a single `.tar.zst`, and exposes deploy-time config as Zarf variables.
Keycloak and the peat node are **platform prerequisites** (provided by the
cluster), not part of this package.

```bash
# Build the image, then create the package (pulls the image from your daemon).
docker build -t keycloak-portal:0.1.3 .
zarf package create deploy/zarf --confirm

# On the target cluster (must be `zarf init`-ed), deploy with your values:
zarf package deploy zarf-package-keycloak-portal-*.tar.zst --confirm \
  --set ISSUER="https://keycloak.example.com/realms/portal" \
  --set HOST="portal.example.com" \
  --set CLIENT_SECRET="<oidc-client-secret>" \
  --set PEAT_NODE_ADDR="peat-node-peat-node.peat-system.svc:50051"
```

Package variables (prompted if omitted): `ISSUER`, `CLIENT_ID`, `CLIENT_SECRET`
(sensitive), `HOST` (also derives the redirect URLs), `GATEWAY`,
`PEAT_NODE_ADDR`, `PEAT_TLS`. Redirect URLs are derived from `HOST`. The Zarf
agent rewrites the bundled image to the in-cluster registry automatically, and
an SBOM is generated at build time.

## Deploy as a UDS bundle

[`deploy/uds`](deploy/uds) defines an **app-only** `UDSBundle` — it contains just
the portal and layers onto an existing UDS platform (Zarf init + UDS Core /
Istio / Keycloak / UDS Operator must already be deployed). When `uds.enabled` is
set (the bundle does this), the chart renders a `uds.dev/v1alpha1` **Package** CR
and the UDS Operator takes over the wiring:

- **SSO** — creates the Keycloak client and writes the secret into
  `keycloak-portal-sso`; the app reads it. You don't supply a client secret.
- **Exposure** — generates the Istio `VirtualService` (chart's own VS is
  disabled under UDS).
- **NetworkPolicies** — default-deny namespace with declared egress to the peat
  node and Keycloak.

```bash
docker build -t keycloak-portal:0.1.3 .
zarf package create deploy/zarf --confirm --output deploy/zarf
uds create deploy/uds --confirm
uds deploy uds-bundle-keycloak-portal-*.tar.zst --confirm \
  --set PORTAL_HOST="portal" \
  --set DOMAIN="example.com"
```

> `PORTAL_HOST` is the **subdomain only** — UDS appends `DOMAIN`
> (`portal` + `example.com` => `portal.example.com`). The redirect URI is built
> from `<PORTAL_HOST>.<DOMAIN>`, and the OIDC issuer defaults to
> `https://sso.<DOMAIN>/realms/uds` (override with `--set ISSUER=…` / `--set REALM=…`).

See the [UDS bundle README](deploy/uds/README.md) for variables. Zarf init, UDS
Core, and the peat node are platform prerequisites.

## Keycloak setup (manual / existing Keycloak)

1. Create (or pick) a **realm**.
2. Create a **client**:
   - Client type: **OpenID Connect**
   - Client authentication: **On** (confidential — yields a client secret)
   - Valid redirect URIs: `http://localhost:3000/auth/callback`
   - Valid post logout redirect URIs: `http://localhost:3000/`
   - Web origins: `http://localhost:3000`
3. Copy the client secret from the client's **Credentials** tab into
   `OIDC_CLIENT_SECRET`.
4. Define **Realm roles** (e.g. `admin`) under *Realm roles*, and/or **Client
   roles** under the client's *Roles* tab. Assign them to users (or to groups).
5. Make sure roles reach the token. With the default `roles` client scope this
   works out of the box; realm roles appear under `realm_access.roles` and
   client roles under `resource_access.<client-id>.roles`.

### Quick local Keycloak (dev only)

```bash
docker run -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Admin console: http://localhost:8080 — create the realm, client, roles, and a
test user, then set `KEYCLOAK_ISSUER=http://localhost:8080/realms/<realm>`.

## Calling the API with a bearer token

```bash
# Obtain a token directly from Keycloak (direct grant must be enabled on the
# client for this shortcut; otherwise use the browser flow).
TOKEN=$(curl -s -X POST \
  "$KEYCLOAK_ISSUER/protocol/openid-connect/token" \
  -d grant_type=password -d client_id="$OIDC_CLIENT_ID" \
  -d client_secret="$OIDC_CLIENT_SECRET" \
  -d username=alice -d password=secret -d scope="openid roles" \
  | jq -r .access_token)

curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/me
curl -H "Authorization: Bearer $TOKEN" http://localhost:3000/api/admin
```

## Project layout

```
cmd/portal/main.go          server wiring + graceful shutdown
internal/config/            env-based configuration + validation
internal/auth/oidc.go       OIDC discovery, OAuth2 flow, token verifiers
internal/auth/middleware.go bearer/cookie auth + role-guard middleware
internal/web/handlers.go    login / callback / logout / dashboard / API
internal/web/templates/     server-rendered HTML
```

## Adding your own protected route

```go
// Any authenticated user:
mux.Handle("GET /reports", s.auth.Authenticate(http.HandlerFunc(handler)))

// Require a realm role:
guard := s.auth.RequireRealmRole("auditor")
mux.Handle("GET /audit", s.auth.Authenticate(guard(http.HandlerFunc(handler))))

// Require a client role:
guard := s.auth.RequireClientRole("keycloak-portal", "editor")
```

Inside a handler, read the verified identity and roles:

```go
claims, _ := auth.ClaimsFromContext(r.Context())
if claims.HasRealmRole("admin") { /* ... */ }
```
