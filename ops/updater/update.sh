#!/bin/sh
# enclave-updater: keeps an operator's stack on the newest release
# (ops/compose/compose.yml, service `updater`).
#
# Every ENCLAVE_UPDATE_INTERVAL seconds (default 3600) it checks each of the
# stack's images at its tag (ENCLAVE_VERSION, default `latest`) with cosign:
# the image must be signed by this repository's release workflow, through
# GitHub's OIDC identity, logged in Rekor. Only if every image passes does
# it pull them by the digest it verified, point the tag at that digest, and
# have compose recreate the containers whose image changed. A tag moved
# between the check and the pull can't slip in: what runs is the verified
# digest. The updater replaces itself last, from a short-lived helper
# container (stopping itself would cut its own compose run short).
#
# It finds its stack from the labels compose put on its own container (the
# project name, folder and compose files), which is mounted at the same
# path as on the host so relative paths in the compose files still work.
set -eu

INTERVAL=${ENCLAVE_UPDATE_INTERVAL:-3600}
TAG=${ENCLAVE_VERSION:-latest}
SERVER=${ENCLAVE_IMAGE:-ghcr.io/0xnullsect0r/enclave-server}
NYM=${ENCLAVE_NYM_IMAGE:-ghcr.io/0xnullsect0r/enclave-nym}
SELF=${ENCLAVE_UPDATER_IMAGE:-ghcr.io/0xnullsect0r/enclave-updater}
IDENTITY=${ENCLAVE_UPDATE_IDENTITY:-'^https://github\.com/0xnullsect0r/enclave-messenger/\.github/workflows/release\.yml@refs/tags/v'}
ISSUER=${ENCLAVE_UPDATE_ISSUER:-https://token.actions.githubusercontent.com}

log() { echo "enclave-updater: $*"; }

# This container's id: Docker mounts its hostname file from a folder named
# after it (the hostname itself is the host's under host networking).
me=$(sed -n 's|.*/containers/\([0-9a-f]\{64\}\)/hostname .*|\1|p' /proc/self/mountinfo | head -n 1)
[ -n "$me" ] || me=$(hostname)
label() { docker inspect "$me" --format "{{index .Config.Labels \"$1\"}}"; }
PROJECT=$(label com.docker.compose.project)
DIR=$(label com.docker.compose.project.working_dir)
FILES=$(label com.docker.compose.project.config_files)
if [ -z "$PROJECT" ] || [ -z "$DIR" ]; then
  log "not started by docker compose"
  exit 1
fi

# The compose files, in order (compose takes them from COMPOSE_FILE).
COMPOSE_FILE=$(echo "$FILES" | tr ',' ':')
export COMPOSE_FILE
compose() {
  docker compose --project-name "$PROJECT" --project-directory "$DIR" "$@"
}

# The digest cosign verified for REF, or nothing.
verified() {
  cosign verify --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$1" 2>/dev/null \
    | grep -o '"docker-manifest-digest":"sha256:[0-9a-f]*"' | head -n 1 | cut -d'"' -f4
}

round() {
  pinned=""
  for repo in "$SERVER" "$NYM" "$SELF"; do
    d=$(verified "$repo:$TAG") || d=""
    if [ -z "$d" ]; then
      log "$repo:$TAG has no valid release signature; not updating"
      return 0
    fi
    pinned="$pinned $repo@$d"
  done
  changed=""
  for ref in $pinned; do
    repo=${ref%@*}
    before=$(docker image inspect "$repo:$TAG" --format '{{.Id}}' 2>/dev/null || true)
    docker pull --quiet "$ref" > /dev/null
    docker tag "$ref" "$repo:$TAG"
    after=$(docker image inspect "$repo:$TAG" --format '{{.Id}}')
    [ "$before" = "$after" ] || changed="$changed $repo"
  done
  [ -n "$changed" ] || return 0
  log "new release images:$changed"
  # Everything but this updater: recreated where its image changed.
  services=$(compose config --services | grep -vx updater || true)
  # shellcheck disable=SC2086
  compose up -d --pull never --no-deps --remove-orphans $services
  docker image prune -f --filter "label=org.opencontainers.image.source=https://github.com/0xnullsect0r/enclave-messenger" > /dev/null || true
  running=$(docker inspect "$me" --format '{{.Image}}')
  if [ "$running" != "$(docker image inspect "$SELF:$TAG" --format '{{.Id}}')" ]; then
    log "replacing the updater itself"
    docker run -d --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$DIR:$DIR:ro" -w "$DIR" \
      -e COMPOSE_FILE --entrypoint docker "$SELF:$TAG" \
      compose --project-name "$PROJECT" --project-directory "$DIR" \
      up -d --pull never --no-deps updater > /dev/null
  fi
}

log "stack $PROJECT in $DIR, following $TAG every ${INTERVAL}s"
while :; do
  round || log "this round failed; trying again next time"
  sleep "$INTERVAL"
done
