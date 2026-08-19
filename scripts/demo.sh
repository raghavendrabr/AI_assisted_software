#!/usr/bin/env bash
# End-to-end demo: append -> query -> verify -> redact -> archive -> export -> tamper & detect.
#
# Prereqs: the service is running on $BASE (default http://localhost:8080) with a reachable
# PostgreSQL started via docker compose (container name audit-postgres). Set the API keys to your
# configured values (WRITER / COMPLIANCE_READER / ADMIN). Under the 'local' profile with the
# provided example config these default keys work.
#
# Usage:
#   AUDIT_WRITER_KEY=... AUDIT_COMPLIANCE_KEY=... AUDIT_ADMIN_KEY=... scripts/demo.sh
set -euo pipefail

BASE="${BASE:-http://localhost:8080/api/v1}"
WRITER_KEY="${AUDIT_WRITER_KEY:-writer-dev-key}"
COMP_KEY="${AUDIT_COMPLIANCE_KEY:-compliance-dev-key}"
ADMIN_KEY="${AUDIT_ADMIN_KEY:-admin-dev-key}"
PG_CONTAINER="${PG_CONTAINER:-audit-postgres}"

say() { printf '\n=== %s ===\n' "$1"; }

# Safety: only ever touch THIS project's dedicated Compose PostgreSQL container. Refuse to run
# against any other/unknown container so the demo can never affect an unrelated database.
if ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  echo "Refusing to run: expected the project's Compose container '$PG_CONTAINER' to be running." >&2
  echo "Start it with: docker compose up -d   (this demo never touches other containers)." >&2
  exit 1
fi
# This demo never deletes data volumes and never runs 'docker compose down -v'. It only issues a
# single UPDATE against the disposable demo database to prove tamper-detection.

say "1. Append a client-account event (with a redactable field)"
curl -s -H "X-API-Key: $WRITER_KEY" -H 'Content-Type: application/json' \
  -X POST "$BASE/audit/events" -d '{
    "eventType":"CLIENT_ACCOUNT_VIEWED","actorId":"emp-1","actorType":"EMPLOYEE",
    "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","outcome":"SUCCESS",
    "businessReason":"customer support",
    "payload":{"accountNumber":"1234567890","channel":"WEB"},
    "redactableFields":["accountNumber"]
  }'
echo

say "2. Query events for acct-1"
curl -s -H "X-API-Key: $COMP_KEY" "$BASE/audit/events?resourceId=acct-1&limit=50"
echo

say "3. Verify the chain (expect intact:true)"
curl -s -H "X-API-Key: $COMP_KEY" "$BASE/audit/verify"
echo

say "4. Redact accountNumber on sequence 1 (ADMIN); chain must stay intact"
curl -s -H "X-API-Key: $ADMIN_KEY" -H 'Content-Type: application/json' \
  -X POST "$BASE/audit/events/1/redact" -d '{"field":"accountNumber"}'
echo
curl -s -H "X-API-Key: $COMP_KEY" "$BASE/audit/verify"
echo

say "5. Export a signed bundle for acct-1"
curl -s -H "X-API-Key: $COMP_KEY" "$BASE/audit/export?resourceId=acct-1" -o /tmp/audit-bundle.json
echo "wrote /tmp/audit-bundle.json ($(wc -c < /tmp/audit-bundle.json) bytes)"

say "6. CORE PROOF: tamper a row directly in PostgreSQL, then re-verify"
docker exec "$PG_CONTAINER" psql -U audit -d audit \
  -c "UPDATE audit_event SET actor_id='attacker' WHERE sequence_number=1;" >/dev/null
echo "tampered sequence 1 (actor_id -> attacker)"
curl -s -H "X-API-Key: $COMP_KEY" "$BASE/audit/verify"
echo

say "Demo complete. Expect step 6 to report intact:false with a CONTENT_HASH_MISMATCH."
