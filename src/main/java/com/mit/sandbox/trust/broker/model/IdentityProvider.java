package com.mit.sandbox.trust.broker.model;

import java.util.List;

public record IdentityProvider(
        String jwksUrl,
        long jwksCacheTtlSeconds,
        List<String> allowedAudiences,
        ClaimMapping mapping
) {
}
