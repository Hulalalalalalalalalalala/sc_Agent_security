# Portable Container Build for Lineage Capability Tree (Milestones 1-5)
# - Cached local build (default when `ghcr.io/rossoctl/examples/weather_tool:pinned` exists):
#   zero network pulls, reuses pre-installed `/app/.venv` (Python 3.12 + cryptography + httpx).
# - Standalone GitHub clone build (`--build-arg BASE_IMAGE=python:3.12-slim`):
#   automatically provisions `/app/.venv` from `lineage/requirements.txt`.
ARG BASE_IMAGE=ghcr.io/rossoctl/examples/weather_tool:pinned
FROM ${BASE_IMAGE}

WORKDIR /opt/lct
ENV PYTHONPATH=/opt/lct \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

COPY lineage/requirements.txt /opt/lct/lineage/requirements.txt
RUN if [ ! -x /app/.venv/bin/python3 ]; then \
      python3 -m venv /app/.venv && \
      /app/.venv/bin/pip install --no-cache-dir -r /opt/lct/lineage/requirements.txt; \
    fi

COPY lineage/__init__.py /opt/lct/lineage/__init__.py
COPY lineage/common /opt/lct/lineage/common
COPY lineage/a2a /opt/lct/lineage/a2a
COPY lineage/federation /opt/lct/lineage/federation
COPY lineage/identity /opt/lct/lineage/identity
COPY lineage/registry /opt/lct/lineage/registry
COPY lineage/protocol /opt/lct/lineage/protocol
COPY lineage/revocation /opt/lct/lineage/revocation
COPY lineage/verifier /opt/lct/lineage/verifier
COPY lineage/audit /opt/lct/lineage/audit
COPY lineage/resilience /opt/lct/lineage/resilience
COPY lineage/sidecar /opt/lct/lineage/sidecar
COPY lineage/agents /opt/lct/lineage/agents
COPY lineage/k8s/__init__.py /opt/lct/lineage/k8s/__init__.py
COPY lineage/k8s/bootstrap_services.py /opt/lct/lineage/k8s/bootstrap_services.py
COPY lineage/k8s/e2e_driver.py /opt/lct/lineage/k8s/e2e_driver.py
COPY lineage/multihost /opt/lct/lineage/multihost

ENTRYPOINT ["/app/.venv/bin/python3", "-m", "lineage.k8s.bootstrap_services"]
