# End-to-End Demo

Exercises the whole service: append → query → verify → redact → archive → export → **tamper &
detect**, plus a **security & observability hardening** section (request limits, Swagger gating, auth,
health probes, Prometheus, correlation IDs, ECS logs). Two ways to run it: the automated script, or
the manual curl walkthrough. No private keys, tokens, or live identity provider are required.

## Prerequisites

- JDK 21, Docker (running), and this repo.
- Test/dev API keys and the ephemeral export dev key are enabled under the `local` profile.

## Option A — automated script

```
docker compose up -d                     # PostgreSQL 16
SPRING_PROFILES_ACTIVE=local ./mvnw spring-boot:run &   # start the service (Flyway applies V1–V3)
# wait until http://localhost:8080 is up, then:
scripts/demo.sh
```
`scripts/demo.sh` appends events, queries, verifies (intact), redacts a field, archives an old
prefix, exports a signed bundle, then **tampers a row directly in PostgreSQL and re-verifies**
(broken, with the violation type) — printing each step.

## Option B — manual walkthrough (curl)

Keys below are the **local dev keys** (see `application.yml` / test config); use your real keys in
any non-local environment.

```bash
BASE=http://localhost:8080/api/v1
WRITER='-H X-API-Key:writer-dev-key'        # replace with your configured WRITER key
COMP='-H   X-API-Key:compliance-dev-key'    # COMPLIANCE_READER
ADMIN='-H  X-API-Key:admin-dev-key'         # ADMIN
```

### 1. Append (WRITER)
```bash
curl -s $WRITER -H 'Content-Type: application/json' -X POST $BASE/audit/events -d '{
  "eventType":"CLIENT_ACCOUNT_VIEWED","actorId":"emp-1","actorType":"EMPLOYEE",
  "resourceType":"CLIENT_ACCOUNT","resourceId":"acct-1","outcome":"SUCCESS",
  "businessReason":"customer support",
  "payload":{"accountNumber":"1234567890","channel":"WEB"},
  "redactableFields":["accountNumber"]
}'
```

### 2. Query (COMPLIANCE_READER)
```bash
curl -s $COMP "$BASE/audit/events?resourceId=acct-1&limit=50"
```

### 3. Verify — expect intact
```bash
curl -s $COMP $BASE/audit/verify        # {"intact":true,...}
```

### 4. Redact a field (ADMIN) — chain stays intact
```bash
curl -s $ADMIN -H 'Content-Type: application/json' \
  -X POST $BASE/audit/events/1/redact -d '{"field":"accountNumber"}'
curl -s $COMP $BASE/audit/verify        # still intact; the value is now null, backed by an amendment
```

### 5. Archive old records (ADMIN)
```bash
curl -s $ADMIN -H 'Content-Type: application/json' \
  -X POST $BASE/audit/retention/archive -d '{"olderThan":"2030-01-01T00:00:00Z"}'
curl -s $COMP $BASE/audit/verify        # intact across active + archive
```

### 6. Signed export + offline verify (COMPLIANCE_READER)
```bash
curl -s $COMP "$BASE/audit/export?resourceId=acct-1" -o bundle.json
# Verify the bundle with NO database, using the standalone verifier. Build the runtime
# classpath once, then run ExportVerifyMain (use ';' as the classpath separator on Windows):
./mvnw -q dependency:build-classpath -Dmdep.outputFile=cp.txt
java -cp "target/classes:$(cat cp.txt)" \
  com.raghavendra.audit.export.ExportVerifyMain bundle.json      # -> VALID: bundle is valid
# Optionally pass a trusted public key as a second argument (recommended; the embedded key
# only proves internal consistency, not authenticity):
#   java -cp "target/classes:$(cat cp.txt)" ...ExportVerifyMain bundle.json trusted_public.b64
```

### 7. The core proof — tamper directly in PostgreSQL, then re-verify
```bash
docker exec audit-postgres psql -U audit -d audit \
  -c "UPDATE audit_event SET actor_id='attacker' WHERE sequence_number=1;"
curl -s $COMP $BASE/audit/verify
# {"intact":false,"firstInconsistentSequence":1,"violationType":"CONTENT_HASH_MISMATCH",...}
```

## Security & observability hardening checks

These exercise the post-review hardening (ADRs 0010–0012). They need **no** private keys, tokens, or
a live identity provider. `B=http://localhost:8080` (base host); `API=$B/api/v1`.

```bash
B=http://localhost:8080; API=$B/api/v1
code() { curl -s -o /dev/null -w "%{http_code}\n" "$@"; }
```

### Request hardening (Commit A)
```bash
# Valid request already shown above (201). Oversized body → 413 (build a >64 KiB body in a file):
python - <<'PY' > /tmp/big.json
print('{"eventType":"X","actorId":"a","actorType":"U","resourceType":"CLIENT_ACCOUNT",'
      '"resourceId":"r","outcome":"SUCCESS","payload":{"note":"' + "x"*200000 + '"}}')
PY
code -X POST "$API/audit/events" -H "X-API-Key: writer-dev-key" \
  -H 'Content-Type: application/json' --data-binary @/tmp/big.json         # -> 413
# Deeply-nested JSON → safe 400 (no payload echoed):
code -X POST "$API/audit/events" -H "X-API-Key: writer-dev-key" \
  -H 'Content-Type: application/json' \
  -d "{\"eventType\":\"X\",\"actorId\":\"a\",\"actorType\":\"U\",\"resourceType\":\"CLIENT_ACCOUNT\",\"resourceId\":\"r\",\"outcome\":\"S\",\"payload\":$(python -c 'print("{\"a\":"*40+"1"+"}"*40)')}"   # -> 400
```

### Swagger gating
```bash
# Default profile: docs NOT public (denied). Under the local profile they ARE public.
code "$B/v3/api-docs"                                # default profile: 401  |  local profile: 200
```

### API-key authentication (401 / 403 / success)
```bash
code "$API/audit/verify"                              # no key            -> 401
code "$API/audit/verify" -H "X-API-Key: writer-dev-key"     # wrong role -> 403
code "$API/audit/verify" -H "X-API-Key: compliance-dev-key" # correct    -> 200
```

### JWT (configuration instructions — no committed key/token/IdP)
JWT is **off by default**. A Bearer token while disabled is rejected, and supplying both a Bearer and
an API key is rejected as ambiguous:
```bash
code "$API/audit/verify" -H "Authorization: Bearer any.token.value"                       # JWT off -> 401
code "$API/audit/verify" -H "Authorization: Bearer a.b.c" -H "X-API-Key: compliance-dev-key"  # both  -> 400
```
To ENABLE JWT you point the service at your own OAuth2/OIDC provider — **no IdP, key, or token is
committed to this repo**:
```bash
# Provide these (e.g. env vars / application-local.yml) and restart with real values you control:
#   audit.security.jwt.enabled=true
#   audit.security.jwt.issuer-uri=<your issuer>
#   audit.security.jwt.audiences=<your audience>
#   audit.security.jwt.allowed-algorithms=RS256,ES256
# Then call with a token minted by YOUR provider whose scopes map to roles:
#   audit.write -> WRITER, audit.read -> COMPLIANCE_READER, audit.admin -> ADMIN
#   curl -s -H "Authorization: Bearer <your-token>" "$API/audit/verify"
# (The test suite proves the full validation matrix against a REAL decoder using locally-generated
#  keys and an in-test JWKS — see JwtAuthenticationIntegrationTest — so no live IdP is needed to
#  validate behavior.)
```

### Observability — probes, Prometheus, correlation IDs, ECS logs
```bash
# Liveness/readiness are PUBLIC (status only):
code "$B/actuator/health/liveness"                    # -> 200
code "$B/actuator/health/readiness"                   # -> 200
# Full health / Prometheus require ADMIN:
code "$B/actuator/prometheus"                                  # no key -> 401
code "$B/actuator/prometheus" -H "X-API-Key: writer-dev-key"   # non-admin -> 403
code "$B/actuator/prometheus" -H "X-API-Key: admin-dev-key"    # admin -> 200
# Dangerous endpoints are never served (not exposed; fail closed):
code "$B/actuator/env" -H "X-API-Key: admin-dev-key"           # -> 403 (never a sensitive body)

# Correlation ID: your inbound X-Request-Id is echoed on the response:
curl -s -D - -o /dev/null "$API/audit/verify" -H "X-API-Key: compliance-dev-key" \
  -H "X-Request-Id: demo-req-001" | grep -i x-request-id       # -> X-Request-Id: demo-req-001

# Domain metrics appear in the scrape (dotted names translate to _total):
curl -s "$B/actuator/prometheus" -H "X-API-Key: admin-dev-key" | grep '^audit_' | head
# Representative ECS log line (default profile emits ECS JSON; note the requestId + non-secret key id;
# the raw API key and payload values NEVER appear):
#   {"@timestamp":"...","message":"auth method=API_KEY result=SUCCESS reason=valid-key
#    requestId=demo-req-001 principal=compliance_reader-key","requestId":"demo-req-001",...}
```

## Teardown
```bash
docker compose down        # preserves the data volume
docker compose down -v     # also deletes the local database volume
```
