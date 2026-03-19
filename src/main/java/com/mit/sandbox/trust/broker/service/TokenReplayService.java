package com.mit.sandbox.trust.broker.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.mit.sandbox.trust.broker.exception.TokenVerificationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Slf4j
@Service
public class TokenReplayService {

    private final Cache<String, Boolean> cache =
            Caffeine.newBuilder()
                    .expireAfterWrite(1, TimeUnit.HOURS)
                    .maximumSize(100000)
                    .build();

    public void validate(String jti) {

        if (cache.getIfPresent(jti) != null) {
            log.info("Token replay already validated");
            throw new TokenVerificationException("Token replay detected");
        }
        cache.put(jti, true);
    }
}