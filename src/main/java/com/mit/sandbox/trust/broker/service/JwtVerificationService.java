package com.mit.sandbox.trust.broker.service;

import com.mit.sandbox.trust.broker.config.IdentityConfig;
import com.mit.sandbox.trust.broker.exception.TokenVerificationException;
import com.mit.sandbox.trust.broker.model.IdentityProvider;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Slf4j
@RequiredArgsConstructor
@Service
public class JwtVerificationService {

    private final JwksResolverService jwksResolver;
    private final IdentityConfig identityConfig;
    private final TokenReplayService replayService;

    public Map<String, Object> verify(String token) {

        log.info("Verifying foreign identity token");

        try {

            SignedJWT jwt = SignedJWT.parse(token);

            String kid = jwt.getHeader().getKeyID();

            if (kid == null || kid.isBlank()) {
                log.error("Missing 'kid' in JWT header");
                throw new TokenVerificationException("Missing 'kid' in JWT header");
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            String jti = claims.getJWTID();

            replayService.validate(jti);

            String issuer = claims.getIssuer();

            if (issuer == null || issuer.isBlank()) {
                log.error("Missing 'issuer' in JWT claims");
                throw new TokenVerificationException("Missing issuer claim");
            }

            IdentityProvider provider =
                    identityConfig.getProvider(issuer);

            log.info("Issuer validated: {}", issuer);

            RSAKey key = jwksResolver.resolve(issuer, kid);

            RSASSAVerifier verifier =
                    new RSASSAVerifier(key.toRSAPublicKey());

            if (!jwt.verify(verifier)) {
                log.error("Invalid JWT signature for issuer {}", issuer);
                throw new TokenVerificationException("Invalid JWT signature");
            }

            Date expiry = claims.getExpirationTime();

            if (expiry == null || expiry.before(new Date())) {
                log.error("Missing 'expiry' in JWT claims or expired");
                throw new TokenVerificationException("Token expired or missing exp claim");
            }

            validateAudience(claims, provider);

            log.info("JWT verified successfully for issuer {}", issuer);

            return claims.getClaims();

        } catch (TokenVerificationException ex) {
            log.error("Token verification error: {}", ex.getMessage());
            throw ex;

        } catch (Exception ex) {
            log.error("Unexpected error during token verification", ex);
            throw new TokenVerificationException("Token verification failed", ex);
        }
    }

    private void validateAudience(JWTClaimsSet claims, IdentityProvider provider) {

        var audiences = claims.getAudience();

        if (audiences == null || audiences.isEmpty()) {
            log.error("Missing 'audience' in JWT claims");
            throw new TokenVerificationException("Missing audience claim");
        }

        boolean valid =
                audiences.stream()
                        .anyMatch(provider.allowedAudiences()::contains);

        if (!valid) {
            log.error("Invalid audience claims");
            throw new TokenVerificationException(
                    "Invalid audience: " + audiences);
        }
    }
}