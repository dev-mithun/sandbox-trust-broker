package com.mit.sandbox.trust.broker.controller;

import com.mit.sandbox.trust.broker.config.SandboxConfig;
import com.mit.sandbox.trust.broker.service.MockKeyService;
import com.mit.sandbox.trust.broker.service.SandboxKeyService;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RequiredArgsConstructor
@RestController
@RequestMapping("/.well-known")
public class DiscoveryController {

    private final MockKeyService mockKeyService;
    private final SandboxConfig sandboxConfig;
    private final SandboxKeyService sandboxKeyService;

    @GetMapping("/jwks.json")
    public ResponseEntity<Map<String, Object>> jwks() {

        JWKSet jwkSet =
                new JWKSet(sandboxKeyService.getPublicKey());

        return ResponseEntity.ok(jwkSet.toJSONObject());
    }

    @GetMapping("/trust-broker")
    public ResponseEntity<Map<String, Object>> discovery(HttpServletRequest request) {

        String baseUrl =
                request.getScheme() + "://" +
                        request.getServerName() +
                        ":" + request.getServerPort();

        return ResponseEntity.ok(Map.of(
                "issuer", sandboxConfig.issuer(),
                "jwks_uri", baseUrl + "/.well-known/jwks.json",
                "token_endpoint", baseUrl + "/api/v1/token/exchange"
        ));
    }
}