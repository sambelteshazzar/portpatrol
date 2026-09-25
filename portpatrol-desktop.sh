#!/bin/sh
# Double-click launcher: run a scan, then keep the window open on the result.
portpatrol scan
status=$?
printf '\nPress Enter to close...'
read -r _ || true
exit $status
