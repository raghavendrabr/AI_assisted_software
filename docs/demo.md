# End-to-End Demo

Exercises the whole service: append → query → verify → redact → archive → export → **tamper &
detect**. Two ways to run it: the automated script, or the manual curl walkthrough.

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

## Teardown
```bash
docker compose down        # preserves the data volume
docker compose down -v     # also deletes the local database volume
```
