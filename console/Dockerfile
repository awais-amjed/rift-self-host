# The one image this repo builds.
#
# Build from the repository root, not from console/ — the migrations and the
# functions are vendored beside it and both go into the image:
#
#   docker build -f console/Dockerfile -t ghcr.io/awais-amjed/rift-console:latest .
FROM denoland/deno:alpine-2.1.4

# psql parses the migrations (see src/postgres.ts for why not a driver).
RUN apk add --no-cache postgresql-client

# The docker CLI and the compose plugin are how the console drives the rest of
# the stack through the mounted socket — copied from the official image rather
# than installed from Alpine, whose compose lags years behind.
#
# The version is not cosmetic. Compose decides whether a container needs
# recreating by hashing its configuration, and v2 and v5 hash a bind mount
# differently. With Alpine's v2.31 in here and a current v5 on the host, every
# container one side created looked changed to the other: an operator's
# `docker compose up -d` recreated the database the console had started, and
# the console's next start recreated it back. Found when starting Studio took
# the API down. v5.5 here and v5.3 on the host compute the same hash.
COPY --from=docker:29.8.0-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:29.8.0-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

WORKDIR /app

# The release this image is. Recorded in the database when it applies an
# upgrade, so the console can tell what a stack has actually been brought to
# rather than what is merely sitting in the image.
COPY VERSION ./VERSION

COPY console/deno.jsonc ./deno.jsonc
COPY console/src ./src
COPY console/templates ./templates
COPY migrations ./migrations
# From `supabase/functions`, which is the layout the Supabase CLI deploys from,
# to a flat `/app/functions` inside the image, which is what the console reads.
COPY supabase/functions ./functions

# Resolve and compile the dependency graph now, so a container that starts on a
# machine with no outbound network still runs. Without this the first request
# would try to fetch jose from npm.
RUN deno cache /app/src/main.ts /app/src/migrations/cli.ts

# Reads and writes the project directory and the functions volume, runs psql
# and docker, listens, and calls create_server through Kong. Enumerated rather
# than `-A` so the list is a description of what this process may do.
#
# The entry point is absolute because the compose file sets `working_dir` to
# the project directory — it has to, so `docker compose` runs against the right
# one — and that overrides the WORKDIR above. A relative path here resolves
# against the project directory and the container crash-loops on a missing
# module.
CMD ["deno", "run", \
  "--allow-net", \
  "--allow-env", \
  "--allow-read", \
  "--allow-write", \
  "--allow-run=psql,docker", \
  "/app/src/main.ts"]

EXPOSE 8080

# busybox wget rather than `deno eval`: eval does not take permission flags, so
# the Deno version of this check failed on its own arguments and reported the
# container unhealthy while it was serving perfectly well.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --quiet --spider http://127.0.0.1:8080/healthz || exit 1
