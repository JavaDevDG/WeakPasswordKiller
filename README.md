# Weak Password Killer

A small microservice that evaluates password strength. Instead of naive regex rules,
it measures real entropy and checks the password against known data breaches.

## Architecture

Two Spring Boot services:

- **password-gateway** (`:8080`) — entry point: rate limiting, routing, and the web UI.
- **password-validator** (`:8081`) — the evaluation logic.

## Security decisions

- **Real strength, not regex** — uses `zxcvbn4j` to estimate entropy (common passwords, keyboard patterns, dictionary words).
- **Breach check via HIBP** — uses k-anonymity: only the first 5 chars of the SHA-1 hash leave the service, so the password is never exposed. A breached password is forced to score 0.
- **Personal-info check** — rejects passwords that contain the given username or email (`CONTAINS_PERSONAL_INFO`). Both fields are optional.
- **Transparent fail-open** — if HIBP is down, the response says `breachCheckStatus: "UNAVAILABLE"` instead of falsely claiming the password is safe.
- **Input hardening** — password capped at 256 chars (DoS guard); invalid input returns a structured `400` body.
- **Strong suggestion** — for weak passwords, a strong alternative is generated.

## Run

```bash
docker-compose up --build
```

- Web UI: http://localhost:8080
- Gateway API: http://localhost:8080/api/v1/password/evaluate

## Try it

Open the Swagger UI in your browser and send requests directly:

- Gateway: http://localhost:8080/swagger-ui.html
- Validator: http://localhost:8081/swagger-ui.html

**Example request**

```json
{
  "username": "okenobi",
  "email": "o.kenobi@jedi-council.com",
  "password": "Hello there!"
}
```

**Example response**

```json
{
  "score": 0,
  "strength": "VERY_WEAK",
  "compromised": true,
  "breachCheckStatus": "CHECKED",
  "violations": ["COMPROMISED"],
  "warning": "This password has appeared in a data breach. You must not use it!",
  "suggestedStrongPassword": "k9#R!pL2(zQx*8mW"
}
```

## Tests

```bash
cd password-validator
./gradlew test
```

## Possible next steps

- Retry / circuit breaker around the HIBP call (e.g. Resilience4j).
- Metrics and tracing (Micrometer + OpenTelemetry).
