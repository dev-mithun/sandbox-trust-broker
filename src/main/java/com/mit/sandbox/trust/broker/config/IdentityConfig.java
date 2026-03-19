package com.mit.sandbox.trust.broker.config;

import com.mit.sandbox.trust.broker.exception.TokenVerificationException;
import com.mit.sandbox.trust.broker.model.IdentityProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Map;

@Slf4j
@ConfigurationProperties(prefix = "identity")
public record IdentityConfig(
        Map<String, IdentityProvider> providers
) {

    public IdentityProvider getProvider(String issuer) {

        IdentityProvider provider = providers.get(issuer);

        if (provider == null) {
            log.error("Provider not found for issuer: {}", issuer);
            throw new TokenVerificationException("Unknown issuer: " + issuer);
        }

        return provider;
    }
}