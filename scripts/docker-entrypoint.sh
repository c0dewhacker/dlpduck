#!/bin/bash
set -euo pipefail

run_both="${DLPDUCK_RUN_BOTH:-false}"
run_both="${run_both,,}"

case "$run_both" in
    0|false|no|off)
        exec dlpduck "$@"
        ;;
    1|true|yes|on)
        ;;
    *)
        echo "DLPDUCK_RUN_BOTH must be true or false (got: $DLPDUCK_RUN_BOTH)" >&2
        exit 64
        ;;
esac

# In combined mode the remaining arguments are shared by both commands.
# Accept a leading `run` so the switch also works on an existing watcher command.
if [ "${1:-}" = "run" ]; then
    shift
fi

dlpduck run "$@" &
watcher_pid=$!
dlpduck console run "$@" &
console_pid=$!

terminate() {
    kill -TERM "$watcher_pid" "$console_pid" 2>/dev/null || true
}
trap terminate TERM INT

# If either role stops, terminate the other and let Docker restart the unit.
if wait -n "$watcher_pid" "$console_pid"; then
    exit_code=0
else
    exit_code=$?
fi
terminate
wait "$watcher_pid" "$console_pid" 2>/dev/null || true
exit "$exit_code"
