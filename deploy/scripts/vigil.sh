#!/usr/bin/env bash
# Vigil operator CLI. Installed as /usr/local/bin/vigil by get.sh; runs the release's scripts against VIGIL_HOME.
set -euo pipefail
SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPTS/lib.sh"

usage() { cat <<EOF
Usage: vigil <command> [options]        (installation: $DEPLOY_DIR, version $(env_get VIGIL_VERSION))

  status                      service health, readiness and version
  logs [service…] [-f]        recent logs (services: web api worker agents postgres objectstore migrate)
  backup [--online]           consistent backup into $BACKUP_ROOT
  restore <backup-dir> [--yes]
  upgrade [--version X.Y.Z] [--yes]
                              download + verify that release, back up, swap files, pull + verify images, migrate,
                              health-gate (default: latest release). Upgrade one minor version at a time unless
                              the release notes say otherwise.
  rollback [backup-dir] [--yes]
                              return to the version before the last upgrade (restores that upgrade's backup)
  diagnostics                 collect a local, secret-masked diagnostics archive
  uninstall [--purge] [--yes] stop and remove containers; --purge also deletes the data volumes (typed confirmation)
  version                     print the installed version
EOF
}

need_docker() { docker info >/dev/null 2>&1 || die "cannot talk to Docker — run with sudo (or as a member of the docker group)"; }

cmd_status() {
  need_docker; require_env
  info "Vigil $(env_get VIGIL_VERSION) ($INSTALL_MODE mode) in $DEPLOY_DIR"
  dc ps
  if readyz >/dev/null 2>&1; then ok "API ready (/readyz)"; else fail "API not ready — try: vigil logs api; vigil diagnostics"; return 1; fi
  info "web: $(env_get VIGIL_WEB_ORIGIN)"
}

cmd_logs() {
  need_docker; require_env
  local follow=() svcs=()
  while [ $# -gt 0 ]; do case "$1" in -f|--follow) follow=(-f); shift;; -*) die "unknown option $1";; *) svcs+=("$1"); shift;; esac; done
  dc logs --tail 200 "${follow[@]}" "${svcs[@]}"
}

cmd_upgrade() {
  need_docker; require_env
  local to="" yes=()
  while [ $# -gt 0 ]; do case "$1" in
    --version) to="${2:?--version needs a value}"; to="${to#v}"; shift 2;;
    --yes) yes=(--yes); export ASSUME_YES=1; shift;;
    -h|--help) usage; exit 0;;
    *) die "unknown option $1";; esac; done
  if [ "$INSTALL_MODE" = source ]; then
    [ -z "$to" ] || die "source install: check out v$to in $REPO_DIR first, then run 'vigil upgrade' without --version"
    exec bash "$SCRIPTS/upgrade.sh" "${yes[@]}"
  fi
  local from; from="$(env_get VIGIL_VERSION)"
  if [ -z "$to" ]; then to="$(latest_release_version)" || die "could not look up the latest release; pass --version X.Y.Z"; fi
  [[ "$to" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version '$to'"
  case "$(semver_cmp "$to" "$from")" in
    -1) die "$to is older than the installed $from; use 'vigil rollback' to go back";;
    0) info "already on $to; re-applying (images re-pulled and verified)";;
  esac
  local fm tm; fm="$(cut -d. -f1-2 <<<"$from")"; tm="$(cut -d. -f1-2 <<<"$to")"
  if [ "${from%%.*}" = "${to%%.*}" ]; then
    local fmin tmin; fmin="${fm#*.}"; tmin="${tm#*.}"
    if [ $((tmin - fmin)) -gt 1 ]; then
      warn "$from -> $to skips minor versions; upgrade one minor at a time unless the $to release notes say otherwise"
      confirm "Continue anyway?" || die "aborted"
    fi
  else
    warn "major version change $from -> $to: read the release notes first"
    confirm "Continue?" || die "aborted"
  fi

  UPGRADE_STAGE="$(mktemp -d)"; trap 'rm -rf "${UPGRADE_STAGE:-}"' EXIT
  local stage="$UPGRADE_STAGE"
  info "downloading release $to"
  release_download "$to" "$stage" || die "download/verification failed; nothing changed"
  local bundle="$stage/vigil-deploy-$to"
  cp "$DEPLOY_DIR/compose.yaml" "$stage/previous-compose.yaml"

  info "installing release $to files into $DEPLOY_DIR"
  local f
  for f in compose.yaml compose.tls.yaml env.template VERSION empty-credentials.json; do install -m 0644 "$bundle/$f" "$DEPLOY_DIR/$f.new"; mv "$DEPLOY_DIR/$f.new" "$DEPLOY_DIR/$f"; done
  for f in scripts postgres proxy; do
    [ -d "$bundle/$f" ] || continue
    rm -rf "$DEPLOY_DIR/$f.new" "$DEPLOY_DIR/$f.old"; cp -R "$bundle/$f" "$DEPLOY_DIR/$f.new"
    [ -d "$DEPLOY_DIR/$f" ] && mv "$DEPLOY_DIR/$f" "$DEPLOY_DIR/$f.old"
    mv "$DEPLOY_DIR/$f.new" "$DEPLOY_DIR/$f"; rm -rf "$DEPLOY_DIR/$f.old"   # running scripts keep their open inode
  done
  chmod 755 "$DEPLOY_DIR"/scripts/*.sh
  VIGIL_PREVIOUS_COMPOSE="$stage/previous-compose.yaml" bash "$DEPLOY_DIR/scripts/upgrade.sh" --yes
}

cmd_uninstall() {
  need_docker; require_env
  local purge=0
  while [ $# -gt 0 ]; do case "$1" in --purge) purge=1; shift;; --yes) export ASSUME_YES=1; shift;; *) die "unknown option $1";; esac; done
  if [ "$purge" = 1 ]; then
    local host typed; host="$(hostname)"
    warn "--purge permanently deletes the Vigil database and evidence volumes. Backups in $BACKUP_ROOT are kept."
    if [ "${VIGIL_PURGE_CONFIRM:-}" != "$host" ]; then
      [ -t 0 ] || die "--purge needs a terminal to confirm, or VIGIL_PURGE_CONFIRM=$host"
      read -r -p "Type the hostname ($host) to delete all Vigil data: " typed
      [ "$typed" = "$host" ] || die "confirmation did not match; nothing deleted"
    fi
    dc down -v --remove-orphans
    ok "containers and data volumes removed"
  else
    confirm "Stop and remove the Vigil containers? Data volumes are kept." || die "aborted"
    dc down --remove-orphans
    ok "containers removed; data volumes kept (start again with: sudo bash $DEPLOY_DIR/scripts/install.sh --yes)"
  fi
  info "backups: $BACKUP_ROOT"
  info "configuration (secrets): $ENV_FILE — delete $DEPLOY_DIR and /usr/local/bin/vigil yourself once you no longer need them"
}

cmd="${1:-help}"; [ $# -gt 0 ] && shift
case "$cmd" in
  status) cmd_status "$@";;
  logs) cmd_logs "$@";;
  backup) need_docker; exec bash "$SCRIPTS/backup.sh" "$@";;
  restore) need_docker; exec bash "$SCRIPTS/restore.sh" "$@";;
  upgrade) cmd_upgrade "$@";;
  rollback) need_docker; exec bash "$SCRIPTS/rollback.sh" "$@";;
  diagnostics) need_docker; exec bash "$SCRIPTS/diagnostics.sh" "$@";;
  uninstall) cmd_uninstall "$@";;
  version|--version) env_get VIGIL_VERSION;;
  help|-h|--help) usage;;
  *) usage >&2; die "unknown command '$cmd'";;
esac
