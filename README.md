# Weak Password Killer

This project is a microservice designed to evaluate password strength. It is built to meet the high security standards of regulated industries (such as healthcare, government, and finance complying with HIPAA and FedRAMP). It does more than simple regex checks; it uses advanced password entropy analysis and checks against known data breaches.

## Architecture

The project consists of two services:
1. **password-gateway**: A proxy service that handles incoming requests. In a real-world scenario, this would be an API Gateway (like Spring Cloud Gateway) managing authentication, rate limiting, and routing.
2. **password-validator**: The core microservice containing the business logic for password evaluation.

## Key Security Decisions & Assumptions

*   **zxcvbn library**: Instead of relying on naive regular expressions (e.g., "must contain 1 upper, 1 lower, 1 digit"), we use `zxcvbn4j`. This library realistically estimates password entropy by checking for common passwords, keyboard patterns, dates, and dictionary words. It also penalizes passwords that contain the user's username or email, preventing trivial social engineering attacks.
*   **Have I Been Pwned (HIBP) Integration**: NIST guidelines strongly recommend checking new passwords against lists of compromised passwords. This service integrates with the HIBP API using **k-anonymity**. We only send the first 5 characters of the SHA-1 hashed password over the network. The API returns a list of matching hashes, and the comparison happens locally. This guarantees that the user's password is never exposed to the external service.
*   **Strong Password Suggestions**: If a user submits a weak password (score < 3), the service automatically generates and suggests a cryptographically strong alternative password (16 characters, mixed case, numbers, and symbols).
*   **Compromised Password Penalty**: Even if a password is long and complex (e.g., "CorrectHorseBatteryStaple123!"), if it is found in the HIBP database, its score is immediately reduced to 0 (VERY_WEAK).
*   **Personal-Information Check**: The password is explicitly rejected (rule `CONTAINS_PERSONAL_INFO`) if it embeds the supplied **username** or **email** — including the email's local part (before `@`). The comparison is case-insensitive. `username` and `email` are optional: the core entropy + breach evaluation always runs, and the personal-info rule is applied only when those fields are provided. This mirrors NIST SP 800-63B guidance to screen against context-specific words while keeping the endpoint usable in flows where identity data is not available.
*   **Transparent Fail-Open for Breach Checks**: If the HIBP API is unreachable, we do **not** silently report the password as safe. The lookup fails *open* (an outage must never block a user from setting a password) but the response carries `breachCheckStatus: "UNAVAILABLE"` so the client knows the "not compromised" result is unverified rather than confirmed. A successful lookup reports `CHECKED`. HIBP calls also have explicit connect (3s) and request (5s) timeouts so a slow upstream cannot hang the service.
*   **Input Hardening (DoS)**: The `password` field is capped at 256 characters (`@Size`). zxcvbn's analysis cost grows with input length, so an unbounded password would be an easy CPU-exhaustion vector. Invalid input returns a structured `400` body (`{"field": "message"}`) via a global exception handler — never an empty/opaque error.

## Prerequisites

*   Docker and Docker Compose (Recommended)
*   Java 21 & Gradle (If running manually)

## How to Run (Docker Compose)

The easiest way to start both services is using Docker Compose. Run this from the root of the repository:

```bash
docker-compose up --build
```
This will start:
*   **password-validator** on `http://localhost:8081`
*   **password-gateway** on `http://localhost:8080`

## API Documentation (Swagger / OpenAPI)

Once the services are running, you can explore the API and send test requests directly from your browser!

*   **Gateway Swagger UI**: [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)
*   **Validator Swagger UI**: [http://localhost:8081/swagger-ui.html](http://localhost:8081/swagger-ui.html)

## How to Test the API (cURL)

Send a POST request to the Gateway service (Port 8080):

```bash
curl -X POST http://localhost:8080/api/v1/password/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "username": "okenobi",
    "email": "o.kenobi@jedi-council.com",
    "password": "Hello there!"
  }'
```

**Expected Response Example:**

```json
{
  "score": 0,
  "strength": "VERY_WEAK",
  "warning": "This password has appeared in a data breach. You must not use it!",
  "suggestions": [
    "Add another word or two. Uncommon words are better."
  ],
  "compromised": true,
  "violations": ["COMPROMISED", "EASILY_GUESSABLE"],
  "suggestedStrongPassword": "k9#R!pL2(zQx*8mW",
  "breachCheckStatus": "CHECKED"
}
```

## Running Automated Tests

To run the unit tests (which cover the core evaluation logic and HIBP checking rules):

```bash
cd password-validator
./gradlew test
```

## Future Improvements for Production

If this were moving to actual production:
*   **Dockerization**: Provide `Dockerfile` and `docker-compose.yml` for containerized deployment.
*   **Circuit Breaker / Retry**: Implement resilience patterns (e.g., Resilience4j) around the HIBP API call in case it goes down.
*   **Metrics & Tracing**: Add Micrometer and OpenTelemetry for observability.
