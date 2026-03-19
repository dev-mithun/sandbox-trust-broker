package com.mit.sandbox.trust.broker.exception;

public class JwksResolutionException extends RuntimeException {

    public JwksResolutionException(String message) {
        super(message);
    }

    public JwksResolutionException(String message, Throwable cause) {
        super(message, cause);
    }
}