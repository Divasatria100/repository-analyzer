#!/bin/sh
# Fixture hook payload (DATA ONLY — installed into a test git repo's .git/hooks
# by tests to prove retrieval never executes hooks; never run by the suite).
echo executed > "${TMPDIR:-/tmp}/repolens-git-hook-canary.marker"
