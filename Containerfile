# Stigcode — multi-stage container build
#
# Air-gapped deployment notes:
#   - All mapping data (CWE→STIG, CCI→NIST) ships inside the package in
#     src/stigcode/data/ and is installed into site-packages at build time.
#   - Zero network calls at runtime: no external APIs, no downloads.
#   - Runs as non-root (UID 1001) — safe for OpenShift by default.
#
# Build on Linux x86_64:
#   podman build -t stigcode:0.0.1 -f Containerfile .
#
# Build on macOS (for OpenShift / linux/amd64 target):
#   podman build --platform linux/amd64 -t stigcode:0.0.1 -f Containerfile .

# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM registry.redhat.io/ubi9/python-311:latest AS builder

WORKDIR /opt/app-root/src

# Copy only what pip needs to install the package.
# Keeping this layer separate from source lets Docker/Podman cache the dep
# install when only application code changes.
COPY pyproject.toml README.md ./
COPY src/ src/

# Ensure source files are readable by the non-root runtime user (UID 1001).
RUN find src/ -type f -name "*.py" -exec chmod 644 {} \; && \
    find src/ -type f \( -name "*.yaml" -o -name "*.xml" \) -exec chmod 644 {} \;

# Install the package and its runtime dependencies.
# --no-cache-dir keeps the layer small; all data ships in the package itself.
RUN pip install --no-cache-dir .

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM registry.redhat.io/ubi9/python-311:latest

WORKDIR /opt/app-root/src

# Copy the fully-installed Python environment from the builder stage.
# The mapping databases and STIG metadata travel with the installed package
# inside site-packages/stigcode/data/ — no separate COPY needed.
COPY --from=builder /opt/app-root/lib /opt/app-root/lib
COPY --from=builder /opt/app-root/bin /opt/app-root/bin

# Smoke-test: verify the CLI entry point resolves and the data layer loads.
# This will fail the build if mappings or CCI data are missing from the image.
RUN stigcode version

# /data is the conventional mount point for SARIF inputs and report outputs.
RUN mkdir -p /data && chown 1001:0 /data && chmod 775 /data
VOLUME ["/data"]

# Drop to non-root. OpenShift assigns a random UID >= 1000; GID 0 membership
# ensures the app can still write to /data when the UID is arbitrary.
USER 1001

ENTRYPOINT ["stigcode"]
CMD ["--help"]
