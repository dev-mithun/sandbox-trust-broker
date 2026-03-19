package com.mit.sandbox.trust.broker.service;

import com.mit.sandbox.trust.broker.config.IdentityConfig;
import com.mit.sandbox.trust.broker.model.ClaimMapping;
import com.mit.sandbox.trust.broker.model.IdentityProvider;
import com.mit.sandbox.trust.broker.util.ClaimConstants;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class ClaimNormalizationService {

    private final IdentityConfig config;

    public ClaimNormalizationService(IdentityConfig config) {
        this.config = config;
    }

    public Map<String, Object> normalize(Map<String, Object> claims) {

        String issuer = (String) claims.get(ClaimConstants.CLAIM_ISS);

        IdentityProvider provider = config.getProvider(issuer);

        ClaimMapping mapping = provider.mapping();

        String subject = (String) claims.get(mapping.subject());
        String givenName = (String) claims.get(mapping.givenName());
        String familyName = (String) claims.get(mapping.familyName());

        Map<String, Object> normalized = new HashMap<>();

        normalized.put("sub", subject);
        normalized.put("iss", issuer);
        normalized.put("fullName", givenName + " " + familyName);
        normalized.put("azp", claims.get("azp"));
        normalized.put("loa", claims.get("loa"));

        return normalized;
    }
}