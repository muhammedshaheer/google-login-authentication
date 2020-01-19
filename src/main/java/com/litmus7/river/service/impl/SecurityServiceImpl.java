package com.litmus7.river.service.impl;

import com.litmus7.river.auth.AccessTokenServices;
import com.litmus7.river.service.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SecurityServiceImpl implements SecurityService {

    @Value("${security.auth.google.client.clientId}")
    private String clientId;

    private AccessTokenServices tokenServices;

    @Override
    public void invalidateTokens(final String username) {
        tokenServices.revokeTokenByUsername(username);
    }

    @Override
    public OAuth2AccessToken createToken(Authentication authentication) {
        Map<String, String> params = new HashMap<>();
        OAuth2Request oauth2Request = new OAuth2Request(params, clientId, null, true, Collections.singleton("all"),
                null, "/login/google", null, null);
        OAuth2Authentication oauth2Auth = new OAuth2Authentication(oauth2Request, authentication);
        return tokenServices.createAccessToken(oauth2Auth);
    }

    public void setTokenServices(AccessTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }
}
