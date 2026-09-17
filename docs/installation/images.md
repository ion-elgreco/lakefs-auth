# Container images

Each release publishes two hardened images, for `linux/amd64` and `linux/arm64`:

```text
ghcr.io/ion-elgreco/lakefs-authn:<version>
ghcr.io/ion-elgreco/lakefs-authz:<version>
```

`<version>` is a release from the [releases page](https://github.com/ion-elgreco/lakefs-auth/releases).
The tag `latest` follows the newest release. Pin a version in production. Each tag is a manifest list, so a
`docker pull` picks the architecture of the host. Linux is the only operating system: the servers run on
Docker Desktop for macOS or Windows through its Linux virtual machine, as any Linux container does.

## Hardened by default

The images are built to expose as little as possible:

- **Distroless base.** They build on `gcr.io/distroless/cc-debian12:nonroot` and contain the server binary and
  nothing else: no shell, no package manager, no interpreter.
- **Non-root.** The process runs as UID and GID 65532, and the image sets that user itself.
- **No writes.** The servers write nothing to disk, so the containers run with a read-only root filesystem,
  no privilege escalation, and all capabilities dropped. The Docker example and the Helm chart set this.
- **Stripped, optimised binary.** The release build strips symbols and uses link-time optimisation.
- **Clean shutdown.** The container stops on SIGTERM and finishes in-flight requests first.
- **Signed supply chain.** Every image carries an SBOM and SLSA provenance, see below.

There is no shell for an exec probe, so use the health endpoints from [Operations](../operations.md) as HTTP
probes.

## Provenance

Each release pushes the images with an SBOM and SLSA provenance. Verify an image before you deploy it:

```bash
gh attestation verify oci://ghcr.io/ion-elgreco/lakefs-authz:<version> --owner ion-elgreco
```

The binaries also ship as tarballs with checksums and provenance on the releases page, for a setup without
containers.
