# Logs

`session-truncated.log` is a raw `script` recording and contains terminal
control sequences, including a recorded `exit`. Displaying it with `cat`,
`head`, `cat -v` or `scriptreplay` will send those bytes to your terminal
and close your shell.

Inspect it safely with:

    od -c session-truncated.log | tail -20
    tr -d '\000' < session-truncated.log | wc -c

The file measures 14234 bytes, of which 194 are content — the rest are
nulls left by the truncation described in Failure 37.
