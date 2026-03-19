package com.mit.sandbox.trust.broker.exception;

public class TokenVerificationException extends RuntimeException {

    public TokenVerificationException(String message) {
        super(message);
    }

    public TokenVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}