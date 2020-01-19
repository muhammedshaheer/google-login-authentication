package com.litmus7.river.auth;

import com.litmus7.river.exception.GoogleAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GoogleAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

    protected GoogleAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            String idToken = request.getParameter("idToken");
            Authentication preAuthenticatedAuthenticationToken = new PreAuthenticatedAuthenticationToken(idToken, idToken);
            return getAuthenticationManager().authenticate(preAuthenticatedAuthenticationToken);
        } catch (AuthenticationException e) {
            throw new GoogleAuthenticationException("Failed to authenticate the token");
        }
    }
}
