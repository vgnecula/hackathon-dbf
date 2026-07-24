#!/usr/bin/env bash
# Scripted end-to-end demo (rlint.md §9 / PLAN.md §9). Run from repo root.
#
# Backup path: if this fails live, the 15:00 backup video is the fallback —
# see PLAN.md §6 hard checkpoints. This script is what that video records.
set -euo pipefail

ENV_ID="${1:-csv_stats}"
SANDBOX_BACKEND="${RLINT_SANDBOX:-local}"

export RLINT_SANDBOX="$SANDBOX_BACKEND"

echo "== rlint demo :: env=${ENV_ID} sandbox=${SANDBOX_BACKEND} =="

echo
echo "-- 1. attack (in-band grading) — every attacker should score reward 1.0 --"
rlint attack "$ENV_ID" --attackers all --grading inband

echo
echo "-- 2. report — coverage table, recall number --"
rlint report "$ENV_ID"

echo
echo "-- 3. patch — harden the environment based on the report --"
rlint patch "$ENV_ID"

echo
echo "-- 4. attack again against the patched env, out-of-band grading --"
rlint attack "${ENV_ID}-patched" --attackers all --grading oob

echo
echo "-- 5. report — exploits should now fail --"
rlint report "${ENV_ID}-patched"

echo
echo "== done =="
