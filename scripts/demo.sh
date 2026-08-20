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

# ---------------------------------------------------------------------------------------------
# Security & observability hardening checks (ADRs 0010-0012). These require NO private keys,
# tokens, or live identity provider. HOST is the base host, derived from BASE (= HOST + /api/v1).
# ---------------------------------------------------------------------------------------------
HOST="${HOST:-${BASE%/api/v1}}"
code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

say "7. Request hardening: oversized body -> 413"
# Build a >64 KiB body in a temp file (never printed) so the OS arg limit is not hit.
BIG_FILE="$(mktemp)"
{ printf '{"eventType":"X","actorId":"a","actorType":"U","resourceType":"CLIENT_ACCOUNT","resourceId":"r","outcome":"SUCCESS","payload":{"note":"';
  head -c 200000 < /dev/zero | tr '\0' 'x';
  printf '"}}'; } > "$BIG_FILE"
printf 'oversized POST -> %s (expect 413)\n' \
  "$(code -X POST "$BASE/audit/events" -H "X-API-Key: $WRITER_KEY" -H 'Content-Type: application/json' --data-binary @"$BIG_FILE")"
rm -f "$BIG_FILE"

say "8. Auth matrix (API key): 401 / 403 / 200"
printf 'no key      -> %s (expect 401)\n' "$(code "$BASE/audit/verify")"
printf 'writer(role)-> %s (expect 403)\n' "$(code "$BASE/audit/verify" -H "X-API-Key: $WRITER_KEY")"
printf 'compliance  -> %s (expect 200)\n' "$(code "$BASE/audit/verify" -H "X-API-Key: $COMP_KEY")"

say "9. Dual-mode: JWT disabled -> Bearer 401; both credentials -> 400"
printf 'bearer (JWT off) -> %s (expect 401)\n' "$(code "$BASE/audit/verify" -H 'Authorization: Bearer any.token.value')"
printf 'both credentials -> %s (expect 400)\n' "$(code "$BASE/audit/verify" -H 'Authorization: Bearer a.b.c' -H "X-API-Key: $COMP_KEY")"
# NOTE: enabling JWT requires YOUR own OAuth2/OIDC provider + a token you mint. No IdP, key, or
# token is committed here. See docs/demo.md for the exact config keys.

say "10. Observability: probes public; Prometheus ADMIN-only; dangerous endpoints not served"
printf 'liveness            -> %s (expect 200, public)\n' "$(code "$HOST/actuator/health/liveness")"
printf 'readiness           -> %s (expect 200, public)\n' "$(code "$HOST/actuator/health/readiness")"
printf 'prometheus (no key) -> %s (expect 401)\n'          "$(code "$HOST/actuator/prometheus")"
printf 'prometheus (admin)  -> %s (expect 200)\n'          "$(code "$HOST/actuator/prometheus" -H "X-API-Key: $ADMIN_KEY")"
printf 'actuator/env (admin)-> %s (expect 403, never a sensitive body)\n' "$(code "$HOST/actuator/env" -H "X-API-Key: $ADMIN_KEY")"

say "11. Correlation ID: inbound X-Request-Id is echoed on the response"
RID_ECHO="$(curl -s -D - -o /dev/null "$BASE/audit/verify" -H "X-API-Key: $COMP_KEY" -H 'X-Request-Id: demo-req-001' | grep -i '^x-request-id:' | tr -d '\r')"
echo "response header: ${RID_ECHO:-<none>}  (expect demo-req-001)"

say "12. Domain metrics present in the Prometheus scrape (dotted names -> _total)"
curl -s "$HOST/actuator/prometheus" -H "X-API-Key: $ADMIN_KEY" | grep '^audit_' | head -8

say "Demo complete. Step 6 reports intact:false (CONTENT_HASH_MISMATCH); steps 7-12 show the security & observability hardening."
