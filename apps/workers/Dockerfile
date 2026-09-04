# SentinelForge workers — containerized pipeline (Module 2).
# Build: docker build -f apps/workers/Dockerfile -t sentinelforge/workers .
# Heavy extractors (binwalk/unblob/sasquatch) install below; stages degrade to
# plan-only mode when a tool is absent (see stages/unpack.ts).
FROM node:22-slim
WORKDIR /app/apps/workers
COPY apps/workers/package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY apps/workers/tsconfig.json ./
COPY apps/workers/src ./src
RUN npm run build
# Optional (uncomment for full extraction capability):
# RUN apt-get update && apt-get install -y --no-install-recommends binwalk squashfs-tools unzip \
#   && rm -rf /var/lib/apt/lists \
#   && pip install --no-cache-dir unblob jefferson
CMD ["node", "dist/index.js"]
