package com.mit.sandbox.trust.broker.service;

import com.mit.sandbox.trust.broker.config.SandboxConfig;
import com.mit.sandbox.trust.broker.dto.TokenExchangeRequest;
import com.mit.sandbox.trust.broker.dto.TokenExchangeResponse;
import com.mit.sandbox.trust.broker.util.TokenConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

@RequiredArgsConstructor
@Service
public class TokenExchangeService {

    private final JwtVerificationService verificationService;
    private final ClaimNormalizationService normalizationService;
    private final SandboxTokenService sandboxTokenService;
    private final SandboxConfig sandboxConfig;

    public TokenExchangeResponse exchange(TokenExchangeRequest tokenExchangeRequest) throws Exception {

        Map<String, Object> claims =
                verificationService.verify(tokenExchangeRequest.externalToken());

        Map<String, Object> normalized =
                normalizationService.normalize(claims);

        String sandboxToken =
                sandboxTokenService.generate(normalized, tokenExchangeRequest.targetAudience());

        return new TokenExchangeResponse(
                sandboxToken,
                TokenConstants.TOKEN_TYPE_BEARER,
                sandboxConfig.tokenExpirationSeconds(),
                sandboxConfig.issuer()
        );
    }
}