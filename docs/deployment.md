# Stigcode Deployment Guide

Stigcode is designed for air-gapped environments. All mapping data (CWE→STIG,
CCI→NIST), STIG metadata, and Python dependencies are bundled at install time.
Zero network calls are made at runtime.

## Container deployment

The included `Containerfile` produces a minimal UBI9 Python 3.11 image using a
multi-stage build.

### Build the image

On a Linux x86_64 host:

```bash
podman build -t stigcode:0.0.1 -f Containerfile .
```

On macOS targeting OpenShift (linux/amd64):

```bash
podman build --platform linux/amd64 -t stigcode:0.0.1 -f Containerfile .
```

The build runs `stigcode version` as a smoke test. If the mapping data is
missing or unreadable the build will fail rather than silently produce a broken
image.

### Run locally

Mount a directory containing your SARIF file into `/data` and pass the desired
subcommand:

```bash
# Generate a Markdown evidence report
podman run --rm \
  -v ./results:/data:Z \
  stigcode:0.0.1 \
  report /data/scan.sarif --output /data/evidence.md --format md

# Generate a NIST 800-53 coverage matrix (CSV)
podman run --rm \
  -v ./results:/data:Z \
  stigcode:0.0.1 \
  coverage /data/scan.sarif --format csv --output /data/coverage.csv

# See all available subcommands
podman run --rm stigcode:0.0.1 --help
```

The `:Z` SELinux label is required on RHEL/Fedora hosts with SELinux enforcing.
Use `:z` for shared mounts.

### Push to a registry

```bash
podman tag stigcode:0.0.1 quay.io/yourorg/stigcode:0.0.1
podman push quay.io/yourorg/stigcode:0.0.1
```

For air-gapped registries, export and transfer the image with:

```bash
podman save stigcode:0.0.1 | gzip > stigcode-0.0.1.tar.gz
# Transfer to air-gapped host, then:
podman load < stigcode-0.0.1.tar.gz
```

## OpenShift deployment

All manifests are in `manifests/`. Update the image reference
(`quay.io/yourorg/stigcode:0.0.1`) and PVC name before applying.

### One-off scan Job

```bash
oc apply -f manifests/job.yaml -n <namespace>
oc logs -f job/stigcode-scan -n <namespace>
```

The Job mounts a PVC at `/data`. Place your SARIF file on the PVC before
running. Outputs are written back to `/data`.

For single-use scans where you don't have an existing PVC, create one first:

```bash
oc create -n <namespace> -f - <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: scan-results-pvc
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
EOF
```

### Interactive deployment

The `manifests/deployment.yaml` keeps a pod running (`sleep infinity`) so you
can exec in and run stigcode interactively against files staged on the volume:

```bash
oc apply -f manifests/deployment.yaml -n <namespace>
oc exec -n <namespace> deploy/stigcode -- \
  stigcode report /data/scan.sarif --output /data/evidence.md
```

This is useful during ATO package preparation when you need to run multiple
stigcode subcommands against the same scan results without scheduling a new Job
each time.

### Security context

Both manifests enforce OpenShift-compatible security constraints:

- `runAsNonRoot: true` — runs as UID 1001 (the UBI default non-root user)
- `allowPrivilegeEscalation: false`
- All Linux capabilities dropped
- `seccompProfile: RuntimeDefault`

No modifications are needed to run in a namespace with the `restricted`
SecurityContextConstraint (SCC).

## Pip install (air-gapped)

For environments where container runtime is not available, stigcode installs
cleanly via pip.

### Download wheels on an internet-connected machine

```bash
pip download stigcode -d ./stigcode-wheels/
```

This downloads stigcode and all its dependencies as wheel files. Transfer the
`stigcode-wheels/` directory to the air-gapped host.

### Install on the air-gapped host

```bash
pip install --no-index --find-links ./stigcode-wheels/ stigcode
```

Verify the install:

```bash
stigcode version
```

### Offline verification

A verification script is included to confirm data integrity after install:

```bash
python scripts/verify_offline.py
```

This checks that all bundled mapping data is present and readable, loads the
mapping database, and runs a minimal parse→lookup pipeline against a fixture
SARIF file. Expected output ends with `Offline verification passed.`

## RPM packaging

RPM packaging via `pyproject-rpm-macros` is a planned future enhancement. For
the current release, pip install and container are the primary delivery
mechanisms. When RPM packaging is added, the spec file will live at
`packaging/stigcode.spec` and produce a noarch RPM installable via `dnf` on
RHEL 8/9 without an internet connection.

## Version pinning

The version is defined in two places that must stay in sync:

- `pyproject.toml`: `[project] version`
- `src/stigcode/version.py`: `__version__`

Container tags should match the package version exactly to avoid confusion in
air-gapped environments where you cannot pull a newer image on demand.
