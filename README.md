# Sandbox Trust Broker – Token Translation Service

## Overview

This project demonstrates a **Token Translation & Verification Service** used in a cross-border identity interoperability gateway.

The service receives an external identity token (JWT) from a trusted identity provider, verifies it using the issuer’s JWKS endpoint, validates token claims, normalizes identity attributes, and issues a new Sandbox session token.

The service acts as a **federation trust broker**, establishing a unified trust layer across multiple identity providers and enabling secure identity exchange between different systems and sandbox applications.

---

## Key Features

* Dynamic JWKS key resolution based on token issuer
* JWKS caching with provider-specific TTL and asynchronous refresh
* Fallback to last known valid keys in case of JWKS endpoint failure
* JWT signature verification
* Trusted issuer validation
* Audience validation based on configuration
* Token expiration validation
* Identity claim normalization into a sandbox format
* Sandbox session token generation
* Replay protection using `jti` tracking
* Global exception handling for consistent API responses

---

## API

### Token Exchange

**Endpoint**

```
POST /api/v1/token/exchange
```

**Input**
External Token (JWT)

**Output**
Sandbox Session JWT

---

### Mock Identity Provider (for testing)

Generate a test token

```
POST /api/v1/mock/token
```

Retrieve Mock IdP public keys

```
GET /api/v1/mock/jwks.json
```

Retrieve mock token claims

```
GET /api/v1/mock/userinfo
```

---

### Sandbox JWKS (for downstream validation)

Retrieve sandbox public keys

```
GET /.well-known/jwks.json
```

Downstream services use this endpoint to validate sandbox-issued tokens.

---

### Discovery Endpoint

Provides metadata for client integration

```
GET /.well-known/trust-broker
```

**Example response**

```json
{
  "issuer": "http://localhost:8080",
  "jwks_uri": "http://localhost:8080/.well-known/jwks.json",
  "token_endpoint": "http://localhost:8080/api/v1/token/exchange"
}
```

---

## Security Validation

The service validates:

* Token signature using JWKS
* Trusted issuer
* Allowed audience
* Token expiration
* Replay protection using `jti`

---

## Tech Stack

* Java 21+
* Spring Boot 4.x
* Nimbus JOSE + JWT
* Maven

---

## Configuration

Identity providers are configured in `application.yml`.

**Example**

```yaml
identity:

  providers:

    mock-idp:
      jwksUrl: http://localhost:8080/api/v1/mock/jwks.json
      jwksCacheTtlSeconds: 300

      allowedAudiences:
        - sandbox-trust-broker

      mapping:
        subject: sub
        givenName: given_name
        familyName: family_name
```

---

## Running Locally

```bash
mvn clean package
mvn spring-boot:run
```

Application runs on:

```
http://localhost:8080
```

---

## End-to-End Flow

```
External IdP → Gateway → Sandbox Token → Sandbox App
```

1. External IdP issues JWT
2. Client sends token to `/api/v1/token/exchange`
3. Gateway verifies token using Mock JWKS
4. Claims are normalized
5. Sandbox token is issued
6. Downstream service validates via Sandbox JWKS

---

## Sample Tokens

### 🔹 External Token (Mock IdP)

```json
{
  "sub": "123",
  "iss": "mock-idp",
  "aud": "sandbox-trust-broker",
  "given_name": "John",
  "family_name": "Doe",
  "azp": "mock-client-app",
  "loa": "medium",
  "jti": "external-token-id",
  "exp": 1999999999
}
```

---

### 🔹 Token Exchange Request

```json
{
  "externalToken": "<external JWT>",
  "targetAudience": "sandbox-app"
}
```

---

### 🔹 Sandbox Token (Response)

```json
{
  "sub": "sandbox:123",
  "iss": "sandbox-gateway",
  "aud": "sandbox-app",
  "name": "John Doe",
  "idp": "mock-idp",
  "azp": "mock-client-app",
  "loa": "medium",
  "jti": "sandbox-token-id",
  "exp": 1999999999
}
```

---

## Scaling Considerations

* JWKS responses are cached to minimize network calls
* Asynchronous refresh avoids blocking requests during cache expiry
* Stateless design enables horizontal scaling
* Replay protection can be backed by Redis in production

---

## Purpose

This project demonstrates how a **federated identity gateway** can securely translate identity tokens across trust domains while maintaining strong cryptographic verification and scalable architecture.
