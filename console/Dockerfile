# The one image this repo builds.
#
# Build from the repository root, not from console/ — the migrations and the
# functions are vendored beside it and both go into the image:
#
#   docker build -f console/Dockerfile -t riftapp/rift-console:latest .
FROM denoland/deno:alpine-2.1.4

# psql parses the migrations (see src/postgres.ts for why not a driver), and
# the docker CLI plus the compose plugin are how the console drives the rest of
# the stack through the mounted socket.
RUN apk add --no-cache postgresql-client docker-cli docker-cli-compose

WORKDIR /app

COPY console/deno.jsonc ./deno.jsonc
COPY console/src ./src
COPY console/templates ./templates
COPY migrations ./migrations
COPY functions ./functions

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
