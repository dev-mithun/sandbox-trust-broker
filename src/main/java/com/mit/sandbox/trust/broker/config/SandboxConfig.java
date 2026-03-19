package com.mit.sandbox.trust.broker.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "sandbox")
public record SandboxConfig(
        String issuer,
        String audience,
        long tokenExpirationSeconds,
        String privateKeyPath,
        String publicKeyPath,
        String keyId
) {
}