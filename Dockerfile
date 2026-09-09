# ─── Stage 1: builder ──────────────────────────────────────────────────────
# Resolve and install dependencies with uv, then install dlpduck itself as a
# regular (non-editable) package into the same venv — so the runtime stage
# only needs to copy one self-contained directory, not the source tree too.
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.8.22 /uv /uvx /bin/

ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Dependencies first, keyed only on the lockfile, so an edit to dlpduck/
# doesn't invalidate this layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-install-project --no-dev --group docker --no-editable

# Now the project itself. README/LICENSE are required — pyproject.toml
# declares them as build metadata (readme, license-files) and hatchling
# fails the build without them.
COPY dlpduck ./dlpduck
COPY README.md LICENSE ./
# RapidOCR declares desktop OpenCV even though DLPDuck has no GUI. Replace it
# with the API-compatible headless wheel already fetched from the lockfile.
RUN uv sync --locked --no-dev --group docker --no-editable && \
    uv pip uninstall --python /app/.venv/bin/python opencv-python && \
    uv pip install --python /app/.venv/bin/python --reinstall --no-deps \
      opencv-python-headless==5.0.0.93

# ─── Stage 2: runtime ──────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Everything dlpduck touches — archived/quarantined PDFs, the content
# store, the audit log — is sensitive (see config.example.yaml's `umask`).
# A dedicated, unprivileged user keeps that true even if a dependency is
# ever compromised.
RUN groupadd --system dlpduck && \
    useradd --system --gid dlpduck --home-dir /app --no-create-home dlpduck

WORKDIR /app
COPY --from=builder --chown=dlpduck:dlpduck /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

COPY --chmod=755 scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Mount a config file here and pass --config /etc/dlpduck/config.yaml, or
# any other path — nothing in the image assumes this location.
RUN mkdir -p /etc/dlpduck && chown dlpduck:dlpduck /etc/dlpduck

USER dlpduck

# The image runs either role from its command, or both when
# DLPDUCK_RUN_BOTH=true.
#   docker run dlpduck run --config /etc/dlpduck/config.yaml            (watcher daemon)
#   docker run dlpduck console run --config /etc/dlpduck/config.yaml    (admin console)
#   docker run -e DLPDUCK_RUN_BOTH=true dlpduck --config /etc/dlpduck/config.yaml
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]

# Documents the admin console's default bind (console.bind in
# config.example.yaml); irrelevant to a watcher-only container.
EXPOSE 8080
