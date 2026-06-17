# Proto

`peat/sidecar/v1/sidecar.proto` is vendored from
[defenseunicorns/peat-node](https://github.com/defenseunicorns/peat-node)
(`proto/sidecar.proto`) with a `go_package` option added. It defines the
`PeatSidecar` gRPC service the application uses to store data sources as JSON
documents in the local peat node.

Generated Go stubs are committed under `internal/peat/sidecarv1/` so the normal
build needs no protoc. To regenerate after updating the proto:

```bash
# requires protoc, protoc-gen-go, protoc-gen-go-grpc on PATH
protoc \
  --proto_path=proto \
  --go_out=. --go_opt=module=github.com/defenseunicorns/keycloak-portal \
  --go-grpc_out=. --go-grpc_opt=module=github.com/defenseunicorns/keycloak-portal \
  proto/peat/sidecar/v1/sidecar.proto
```

> The proto is pre-1.0 and has had breaking renames (e.g. `Platform` → `Node`).
> Re-vendor and regenerate when bumping the peat node version.
