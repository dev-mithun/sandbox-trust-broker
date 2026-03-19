package com.mit.sandbox.trust.broker.service;

import com.mit.sandbox.trust.broker.config.SandboxConfig;
import com.mit.sandbox.trust.broker.dto.MockTokenRequest;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class MockKeyService {

    private final SandboxConfig config;
    private final RSAKey rsaKey;

    public MockKeyService(SandboxConfig sandboxConfig) throws Exception {
        this.config = sandboxConfig;
        this.rsaKey = new RSAKeyGenerator(2048)
                .keyID("test-key-1")
                .generate();
    }

    public RSAKey getPrivateKey() {
        return rsaKey;
    }

    public JWKSet getJwkSet() {
        return new JWKSet(rsaKey.toPublicJWK());
    }

    public String generateToken(MockTokenRequest request) throws Exception {

        RSAKey rsaKey = getPrivateKey();

        JWSSigner signer = new RSASSASigner(rsaKey);

        Instant now = Instant.now();

        Date issueTime = Date.from(now);

        Date expiryTime =
                Date.from(now.plusSeconds(config.tokenExpirationSeconds()));
        String issuer = Optional.ofNullable(request.issuer()).orElse("mock-idp");
        String subject = Optional.ofNullable(request.subject()).orElse(UUID.randomUUID().toString());
        String authorizedParty = Optional.ofNullable(request.azp()).orElse("mock-client-app");
        String levelOfAssurance = Optional.ofNullable(request.azp()).orElse("medium");
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(issuer)
                .audience("sandbox-trust-broker")
                .claim("full_name", request.givenName() + " " + request.familyName())
                .claim("given_name", request.givenName())
                .claim("family_name", request.familyName())
                .claim("azp", authorizedParty)
                .claim("loa", levelOfAssurance)
                .issueTime(issueTime)
                .notBeforeTime(issueTime)
                .expirationTime(expiryTime)
                .jwtID(UUID.randomUUID().toString())
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                claims
        );

        jwt.sign(signer);

        return jwt.serialize();
    }
}