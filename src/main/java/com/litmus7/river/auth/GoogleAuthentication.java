package com.litmus7.river.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class GoogleAuthentication extends AbstractAuthenticationToken {

    private GoogleAuthorizedUser googleAuthorizedUser;

    public GoogleAuthentication(
            Collection<? extends GrantedAuthority> authorities
            , GoogleAuthorizedUser googleAuthorizedUser
    ) {
        super(authorities);
        this.googleAuthorizedUser = googleAuthorizedUser;
    }

    @Override
    public Object getCredentials() {
        return googleAuthorizedUser.getEmail();
    }

    @Override
    public Object getPrincipal() {
        return googleAuthorizedUser;
    }

    public GoogleAuthorizedUser getGoogleAuthorizedUser() {
        return googleAuthorizedUser;
    }
}
