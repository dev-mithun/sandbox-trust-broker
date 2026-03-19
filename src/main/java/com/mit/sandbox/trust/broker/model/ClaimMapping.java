package com.mit.sandbox.trust.broker.model;

public record ClaimMapping(
        String subject,
        String givenName,
        String familyName
) {
}
