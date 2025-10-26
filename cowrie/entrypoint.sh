#!/usr/bin/env bash
set -euo pipefail

# RUNTIME (aufs Volume gemountet)
mkdir -p /opt/cowrie/var/run /opt/cowrie/var/log

# Persistente Logs (aufs Volume gemountet)
mkdir -p /cowrie/log/tty

# ⚠️ Wichtig: Nur die MOUNT-Dirs chownen, NICHT /cowrie (read-only)!
chown -R cowrie:cowrie /opt/cowrie/var || true
chown -R cowrie:cowrie /cowrie/log     || true

# auf non-root droppen
exec gosu cowrie bin/cowrie start -n
