package com.litmus7.river.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.litmus7.river.dto.ResponseInfo;
import com.litmus7.river.service.SecurityService;
import com.litmus7.river.service.impl.SecurityServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import javax.servlet.Filter;
import javax.sql.DataSource;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;

@Configuration
@EnableResourceServer
@EnableTransactionManagement(proxyTargetClass = true)
public class GoogleLoginResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Value("${security.auth.google.client.clientId}")
    private String googleClientId;

    @Value("${security.auth.processingUrl}")
    private String authenticationProcessingUrl;

    @Value("${security.auth.token.validity}")
    private Integer tokenValidity;

//    @Autowired
//    private SecurityService securityService;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private ObjectMapper mapper;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.cors().disable();
        http.authorizeRequests()
                .antMatchers("/login/google").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(googleAuthFilter(), UsernamePasswordAuthenticationFilter.class)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
                .and()
                .exceptionHandling()
                .authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
                .accessDeniedHandler(new OAuth2AccessDeniedHandler());
        http.setSharedObject(ClientDetailsService.class, clientDetailsService());
    }

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.tokenServices(tokenService());
    }

    @Bean
    Filter googleAuthFilter() {
        GoogleAuthenticationProcessingFilter authenticationProcessingFilter = new GoogleAuthenticationProcessingFilter(authenticationProcessingUrl);
        GoogleUserAuthenticationManager authenticationManager = new GoogleUserAuthenticationManager();
        authenticationManager.setGoogleClientId(googleClientId);
        authenticationProcessingFilter.setAuthenticationManager(authenticationManager);
        authenticationProcessingFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler());
        return authenticationProcessingFilter;
    }

    @Bean
    public SecurityService getSecurityService() {
        SecurityServiceImpl securityService = new SecurityServiceImpl();
        securityService.setTokenServices(tokenService());
        return securityService;
    }

    @Bean
    AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> {
            String username = ((GoogleAuthentication) authentication).getGoogleAuthorizedUser().getEmail();
            getSecurityService().invalidateTokens(username);
            ResponseInfo responseInfo = new ResponseInfo();
            OAuth2AccessToken token = getSecurityService().createToken(authentication);
            responseInfo.setPayload(token);
            try {
                response.getWriter().write(mapper.writeValueAsString(responseInfo));
                response.flushBuffer();
            } catch (Exception e) {
                e.printStackTrace();
            }
        };
    }

    @Bean
    ClientDetailsService clientDetailsService() {
        InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        BaseClientDetails clientDetails = new BaseClientDetails();
        clientDetails.setClientId(googleClientId);
        clientDetails.setScope(Collections.singleton("all"));
        clientDetails.setAuthorizedGrantTypes(new HashSet<>(Arrays.asList("implicit", "refresh_token")));
        clientDetails.setAccessTokenValiditySeconds(tokenValidity);
        HashMap<String, ClientDetails> map = new HashMap<>();
        map.put(clientDetails.getClientId(), clientDetails);
        clientDetailsService.setClientDetailsStore(map);
        return clientDetailsService;
    }

    @Bean
    AccessTokenServices tokenService() {
        AccessTokenServices tokenServices = new AccessTokenServices();
        tokenServices.setTokenStore(tokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(clientDetailsService());
        return tokenServices;
    }

    @Bean
    TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource);
    }

    @Bean
    public FilterRegistrationBean corsFilterConfig() {
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        final CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        final FilterRegistrationBean bean = new FilterRegistrationBean(new CorsFilter(source));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}
