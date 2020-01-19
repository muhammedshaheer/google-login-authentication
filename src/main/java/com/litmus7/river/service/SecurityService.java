package com.litmus7.river.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

public interface SecurityService {
    void invalidateTokens(String username);

    OAuth2AccessToken createToken(Authentication authentication);
}
