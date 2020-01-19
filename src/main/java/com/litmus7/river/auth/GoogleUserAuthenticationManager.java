package com.litmus7.river.auth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.litmus7.river.exception.GoogleAuthenticationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Collections;

public class GoogleUserAuthenticationManager implements AuthenticationManager {

    private String googleClientId;

    @Override
    public Authentication authenticate(Authentication preAuth) throws AuthenticationException {
        GoogleIdTokenVerifier tokenVerifier = new GoogleIdTokenVerifier
                .Builder(new NetHttpTransport(), JacksonFactory.getDefaultInstance())
                .setAudience(Collections.singleton(googleClientId))
                .build();

        GoogleAuthorizedUser googleUser = getGoogleAuthorizedUser(preAuth, tokenVerifier);

        Collection<GrantedAuthority> grantedAuthorities = Collections.emptyList();

        GoogleAuthentication googleAuthentication = new GoogleAuthentication(grantedAuthorities, googleUser);
        googleAuthentication.setAuthenticated(true);
        return googleAuthentication;
    }

    private GoogleAuthorizedUser getGoogleAuthorizedUser(Authentication preAuth, GoogleIdTokenVerifier tokenVerifier) {

        GoogleIdToken googleIdToken;
        try {
            googleIdToken = tokenVerifier.verify((String) preAuth.getPrincipal());
        } catch (GeneralSecurityException e) {
            throw new GoogleAuthenticationException("Authentication with google failed");
        } catch (IOException e) {
            throw new GoogleAuthenticationException("Failed to contact google server");
        }

        if (googleIdToken != null) {
            GoogleAuthorizedUser googleUser = new GoogleAuthorizedUser();
            GoogleIdToken.Payload payload = googleIdToken.getPayload();
            googleUser.setEmail(payload.getEmail());
            googleUser.setEmailVerified(payload.getEmailVerified());
            googleUser.setName((String) payload.get("name"));
            googleUser.setPictureUrl((String) payload.get("picture"));
            googleUser.setLocale((String) payload.get("locale"));
            googleUser.setFamilyName((String) payload.get("family_name"));
            googleUser.setGivenName((String) payload.get("given_name"));
            googleUser.setIdToken((String) preAuth.getPrincipal());

            return googleUser;
        } else {
            throw new GoogleAuthenticationException("Failed to validate google user");
        }
    }

    public void setGoogleClientId(String googleClientId) {
        this.googleClientId = googleClientId;
    }
}
