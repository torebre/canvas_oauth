package com.kjipo.client;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final String authorizationUri;
    private final String tokenUri;
    private final String clientId;
    private final String clientKey;


    public SecurityConfig(@Value("${authorization-uri}") String authorizationUri,
                          @Value("${client-id}") String clientId,
                          @Value("${client-key}") String clientKey,
                          @Value("${token-uri}") String tokenUri) {
        this.authorizationUri = authorizationUri;
        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientKey = clientKey;
    }

    @Order(1)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests((requests) ->
                        requests.anyRequest()
                                .authenticated())
                .oauth2Login(oauth2Login -> {
                    oauth2Login.userInfoEndpoint(userInfoEndpoint -> {
                        // Need to override here to avoid Spring trying to call a userinfo endpoint
                        // since there does not seem to be such an endpoint in canvas
                        userInfoEndpoint.userService(this.oauth2UserService());
                    });
                })
                .build();
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(clientRegistration());
    }

    /**
     * https://docs.spring.io/spring-security/site/docs/5.2.12.RELEASE/reference/html/oauth2.html#oauth2login-register-clientregistrationrepository-bean
     *
     * @return
     */
    private ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("canvas")
                .clientId(clientId)
                .clientSecret(clientKey)
//                .scope("/auth/userinfo")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                // TODO Looks like there is no userinfo endpoint defined for canvas
//                .userInfoUri("http://localhost:8080/login/oauth2/token/auth/userinfo")
//                .userInfoUri("http://localhost:8080/auth/userinfo")
//                .userNameAttributeName("user")
                .build();
    }


    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {

        // TODO Fill in proper values for user

        return new OAuth2UserService<OAuth2UserRequest, OAuth2User>() {
            @Override
            public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
                return new OAuth2User() {
                    @Override
                    public Map<String, Object> getAttributes() {
                        return Map.of("username", "Test user");
                    }

                    @Override
                    public Collection<? extends GrantedAuthority> getAuthorities() {
                        return List.of();
                    }

                    @Override
                    public String getName() {
                        return "Test";
                    }
                };
            }
        };
    }


}
