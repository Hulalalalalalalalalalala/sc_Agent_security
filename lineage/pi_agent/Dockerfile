# =============================================================================
# Lineage Capability Tree (LCT) — Real Open-Source `Pi` Agent Container Image
#
# Runs `@mariozechner/pi-agent-core` + `@mariozechner/pi-ai` strictly bound to
# `127.0.0.1:9001` as a non-root container (`uid=1000`, `fsGroup=2000`) alongside
# the unmodified Python `LineageSidecar` (`lineage-lct`) inside a 2-container Pod.
# =============================================================================
ARG NODE_BASE_IMAGE=node:22-slim
FROM ${NODE_BASE_IMAGE}

WORKDIR /opt/lct/lineage/pi_agent

COPY lineage/pi_agent/package.json lineage/pi_agent/package-lock.json /opt/lct/lineage/pi_agent/
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY lineage/sdk/node/lct_sdk.mjs /opt/lct/lineage/sdk/node/lct_sdk.mjs
COPY lineage/sdk/node/lct_sdk.d.ts /opt/lct/lineage/sdk/node/lct_sdk.d.ts
COPY lineage/pi_agent/server.mjs /opt/lct/lineage/pi_agent/server.mjs

USER node
ENV NODE_ENV=production

ENTRYPOINT ["node", "/opt/lct/lineage/pi_agent/server.mjs", "--port", "9001"]
