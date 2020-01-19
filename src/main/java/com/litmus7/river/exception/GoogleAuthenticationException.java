package com.litmus7.river.exception;

import org.springframework.security.core.AuthenticationException;

public class GoogleAuthenticationException extends AuthenticationException {
    public GoogleAuthenticationException(String msg) {
        super(msg);
    }
}
