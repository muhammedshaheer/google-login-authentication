package com.litmus7.river.auth;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Collection;
import java.util.Optional;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AccessTokenServices extends DefaultTokenServices {

    @Autowired
    private TokenStore tokenStore;

    @Value("${security.auth.google.client.clientId}")
    private String googleClientId;

    @Override
    public OAuth2AccessToken readAccessToken(String tokenValue) {
        OAuth2AccessToken oAuth2AccessToken = tokenStore.readAccessToken(tokenValue);
        try {
            if (oAuth2AccessToken == null) {
                try {
                    String[] pair = new String(Base64.getDecoder().decode(tokenValue), UTF_8).split(";");
                    if (pair.length == 2) {
                        oAuth2AccessToken = readHashedToken(pair[0], pair[1]);
                    }
                } catch (IllegalArgumentException ignore) {
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return oAuth2AccessToken;
    }

    private OAuth2AccessToken readHashedToken(String user, String hashedToken) {
        Collection<OAuth2AccessToken> tokens = tokenStore.findTokensByClientIdAndUserName(googleClientId, user);
        Optional<OAuth2AccessToken> token = tokens.stream()
            .filter(t -> DigestUtils.sha256Hex(t.getValue()).equals(hashedToken)).findFirst();
        return token.orElse(null);
    }

    public String getAccessToken(String username) {
        Collection<OAuth2AccessToken> tokensByClientIdAndUserName = tokenStore.findTokensByClientIdAndUserName(googleClientId, username);
        OAuth2AccessToken oAuth2AccessToken = tokensByClientIdAndUserName.stream().findFirst().orElse(null);
        return oAuth2AccessToken != null ? oAuth2AccessToken.getValue() : null;
    }

    public boolean revokeTokenByUsername(String username) {
        Collection<OAuth2AccessToken> tokensByClientIdAndUserName = tokenStore.findTokensByClientIdAndUserName(googleClientId, username);
        OAuth2AccessToken oAuth2AccessToken = tokensByClientIdAndUserName.stream().findFirst().orElse(null);
        if (oAuth2AccessToken == null) {
            return false;
        }
        return revokeToken(oAuth2AccessToken.getValue());
    }
}
