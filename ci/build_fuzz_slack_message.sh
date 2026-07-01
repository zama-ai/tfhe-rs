#!/usr/bin/env bash
#
# Build a Slack notification env block for the fuzzing workflow's postcampaign step.
# Reads utils/fuzz/summary.md if present; writes SLACK_COLOR and SLACK_MESSAGE to $GITHUB_ENV.
#
# Required env vars:
#   JOB_STATUS      Result of the fuzz job (success/failure/cancelled/...)
#   ACTION_RUN_URL  Link back to the GitHub Actions run
#   GITHUB_ENV      Path to the file where step env vars are written
#
# Optional env vars:
#   SUMMARY         Path to the summary file (default: utils/fuzz/summary.md)

set -euo pipefail

: "${JOB_STATUS:?JOB_STATUS is required}"
: "${ACTION_RUN_URL:?ACTION_RUN_URL is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

SUMMARY="${SUMMARY:-utils/fuzz/summary.md}"

# Crash count comes from summary.md's first line.
crashes=0
if [[ -s "$SUMMARY" ]]; then
    crashes=$(sed -nE '1s/^\*([0-9]+) crashes\*.*/\1/p' "$SUMMARY")
    crashes=${crashes:-0}
fi

case "${JOB_STATUS}" in
    success)
        if (( crashes > 0 )); then
            emoji=":bomb:"; status="crashes found"; color="danger"
        else
            emoji=":white_check_mark:"; status="success"; color="good"
        fi ;;
    failure)   emoji=":x:";              status="failure";   color="danger" ;;
    cancelled) emoji=":warning:";        status="cancelled"; color="warning" ;;
    *)         emoji=":grey_question:";  status="${JOB_STATUS}"; color="" ;;
esac

{
    echo "SLACK_COLOR=${color}"
    echo "SLACK_MESSAGE<<EOF"
    echo "Fuzzing Campaign Report:"
    echo "${emoji} *${status}*"
    echo ""
    if [[ -s "$SUMMARY" ]]; then
        cat "$SUMMARY"
    else
        echo "(workflow failed before postcampaign ran, or disk is full)"
    fi
    echo ""
    echo "<${ACTION_RUN_URL}|View run>"
    echo "EOF"
} >> "$GITHUB_ENV"
