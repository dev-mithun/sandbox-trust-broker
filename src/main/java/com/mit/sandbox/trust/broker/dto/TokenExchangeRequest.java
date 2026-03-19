package com.mit.sandbox.trust.broker.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenExchangeRequest(
        @NotBlank(message = "externalToken must not be empty")
        String externalToken,
        String targetAudience
) {
}