package com.mit.sandbox.trust.broker.dto;

import jakarta.validation.constraints.NotBlank;

public record MockTokenRequest(
        String subject,
        @NotBlank(message = "givenName must not be empty")
        String givenName,
        @NotBlank(message = "familyName must not be empty")
        String familyName,
        String issuer,
        String azp,
        String loa
) {
}
