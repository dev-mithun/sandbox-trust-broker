package com.mit.sandbox.trust.broker.dto;

public record TokenExchangeResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        String issuer
) {
}