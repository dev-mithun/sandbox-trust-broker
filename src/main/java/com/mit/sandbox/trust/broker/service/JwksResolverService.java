package com.mit.sandbox.trust.broker.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.mit.sandbox.trust.broker.config.IdentityConfig;
import com.mit.sandbox.trust.broker.exception.JwksResolutionException;
import com.mit.sandbox.trust.broker.model.IdentityProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.time.Instant;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
@RequiredArgsConstructor
@Service
public class JwksResolverService {

    private final IdentityConfig identityConfig;

    private final Cache<String, CachedJwks> cache =
            Caffeine.newBuilder()
                    .maximumSize(100)
                    .build();

    private final ExecutorService executor =
            Executors.newFixedThreadPool(4);

    public RSAKey resolve(String issuer, String kid) {

        CachedJwks cached = cache.getIfPresent(issuer);

        if (cached == null) {

            log.info("JWKS cache miss for issuer={}, loading", issuer);

            cached = fetchJwks(issuer);

            cache.put(issuer, cached);
        }

        if (cached.isExpired()) {

            log.info("JWKS expired for issuer={}, triggering async refresh", issuer);

            refreshAsync(issuer, cached);
        }

        RSAKey key = cached.findKey(kid);

        if (key == null) {

            log.info("Key not found for issuer={}, kid={}, forcing refresh", issuer, kid);

            CachedJwks refreshed = fetchJwks(issuer);

            cache.put(issuer, refreshed);

            key = refreshed.findKey(kid);

            if (key == null) {

                log.error("Signing key not found after refresh issuer={} kid={}", issuer, kid);

                throw new JwksResolutionException("Signing key not found for kid: " + kid);
            }
        }

        return key;
    }

    /**
     * Async refresh (non-blocking)
     */
    private void refreshAsync(String issuer, CachedJwks existing) {

        executor.submit(() -> {

            try {

                CachedJwks refreshed = fetchJwks(issuer);

                cache.put(issuer, refreshed);

                log.info("JWKS async refresh successful for issuer={}", issuer);

            } catch (Exception ex) {

                log.warn("JWKS async refresh failed for issuer={}, using stale cache", issuer);
            }
        });
    }

    /**
     * Fetch JWKS from provider
     */
    private CachedJwks fetchJwks(String issuer) {

        try {

            IdentityProvider provider =
                    identityConfig.getProvider(issuer);

            JWKSet jwkSet =
                    JWKSet.load(new URI(provider.jwksUrl()).toURL());

            log.info("JWKS fetched successfully for issuer={}", issuer);

            return new CachedJwks(
                    jwkSet,
                    Instant.now().plusSeconds(provider.jwksCacheTtlSeconds())
            );

        } catch (Exception ex) {

            log.error("Failed to fetch JWKS for issuer={}", issuer, ex);

            throw new JwksResolutionException(
                    "Unable to fetch JWKS for issuer: " + issuer, ex);
        }
    }

    /**
     * Cached JWKS wrapper
     */
    private record CachedJwks(
            JWKSet jwkSet,
            Instant expiry
    ) {

        boolean isExpired() {
            return Instant.now().isAfter(expiry);
        }

        RSAKey findKey(String kid) {

            return jwkSet.getKeys()
                    .stream()
                    .filter(k -> kid.equals(k.getKeyID()))
                    .map(k -> (RSAKey) k)
                    .findFirst()
                    .orElse(null);
        }
    }
}