package com.mit.sandbox.trust.broker.controller;

import com.mit.sandbox.trust.broker.dto.TokenExchangeRequest;
import com.mit.sandbox.trust.broker.dto.TokenExchangeResponse;
import com.mit.sandbox.trust.broker.service.TokenExchangeService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1/token")
public class TokenExchangeController {

    private final TokenExchangeService tokenExchangeService;

    @PostMapping("/exchange")
    public ResponseEntity<TokenExchangeResponse> exchange(@Valid @RequestBody TokenExchangeRequest request) throws Exception {
        return ResponseEntity.ok(tokenExchangeService.exchange(request));
    }
}