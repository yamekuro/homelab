if [ -n "$SSH_CONNECTION" ] && [ -z "$SCRIPT_RECORDING" ]; then
    export SCRIPT_RECORDING=1
    LOGFILE="/var/log/session-logs/$(whoami)-$(date +%Y%m%d-%H%M%S)-$$"
    exec script -q -f -c "$SHELL -l" --timing="$LOGFILE.timing" "$LOGFILE.log"
fi
