package com.mit.sandbox.trust.broker.controller;

import com.mit.sandbox.trust.broker.dto.MockTokenRequest;
import com.mit.sandbox.trust.broker.exception.TokenVerificationException;
import com.mit.sandbox.trust.broker.service.MockKeyService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/mock")
public class MockExternalIdentityProviderController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final MockKeyService keyService;

    @PostMapping("/token")
    public ResponseEntity<String> generateToken(
            @Valid @RequestBody MockTokenRequest request) throws Exception {

        String token = keyService.generateToken(request);

        return ResponseEntity.ok(token);
    }

    @GetMapping("/jwks.json")
    public ResponseEntity<Map<String, Object>> mockJwks() {

        JWKSet jwkSet = keyService.getJwkSet();

        return ResponseEntity.ok(jwkSet.toJSONObject());
    }

    @GetMapping("/userinfo")
    public ResponseEntity<Map<String, Object>> userInfo(
            @RequestHeader("Authorization") String authHeader) throws Exception {

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            throw new TokenVerificationException("Missing or invalid Authorization header");
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        SignedJWT jwt = SignedJWT.parse(token);

        JWTClaimsSet claims = jwt.getJWTClaimsSet();

        return ResponseEntity.ok(Map.of(
                "sub", claims.getSubject(),
                "given_name", claims.getStringClaim("given_name"),
                "family_name", claims.getStringClaim("family_name"),
                "issuer", claims.getIssuer()
        ));
    }
}