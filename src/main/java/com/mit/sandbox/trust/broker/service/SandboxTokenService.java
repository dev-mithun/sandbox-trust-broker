package com.mit.sandbox.trust.broker.service;

import com.mit.sandbox.trust.broker.config.SandboxConfig;
import com.mit.sandbox.trust.broker.exception.TokenVerificationException;
import com.mit.sandbox.trust.broker.util.ClaimConstants;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RequiredArgsConstructor
@Service
public class SandboxTokenService {

    private final SandboxKeyService keyService;
    private final SandboxConfig sandboxConfig;

    public String generate(Map<String, Object> claims, String targetAudience) throws Exception {

        JWSSigner signer =
                new RSASSASigner(keyService.getRsaKey());

        String subject = (String) claims.get(ClaimConstants.CLAIM_SUB);

        if (subject == null || subject.isBlank()) {
            throw new TokenVerificationException("Missing subject claim in token");
        }

        String foreignIssuer = (String) claims.get(ClaimConstants.CLAIM_ISS);

        Instant now = Instant.now();

        Date issueTime = Date.from(now);

        Date expiryTime =
                Date.from(now.plusSeconds(sandboxConfig.tokenExpirationSeconds()));

        String audience =
                targetAudience != null && !targetAudience.isBlank()
                        ? targetAudience
                        : sandboxConfig.audience();
        String fullName = (String) claims.get("fullName");
        String azp = (String) claims.getOrDefault("azp", "unknown-client");
        String loa = (String) claims.getOrDefault("loa", "medium");
        JWTClaimsSet claimSet =
                new JWTClaimsSet.Builder()
                        .subject(foreignIssuer + ":" + subject)
                        .claim("name", fullName)
                        .claim("idp", foreignIssuer)
                        .claim("azp", azp)
                        .claim("loa", loa)
                        .issuer(sandboxConfig.issuer())
                        .audience(audience)
                        .issueTime(issueTime)
                        .notBeforeTime(issueTime)
                        .expirationTime(expiryTime)
                        .jwtID(UUID.randomUUID().toString())
                        .build();

        SignedJWT jwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.RS256)
                                .keyID(keyService.getRsaKey().getKeyID())
                                .build(),
                        claimSet);

        jwt.sign(signer);

        return jwt.serialize();
    }
}