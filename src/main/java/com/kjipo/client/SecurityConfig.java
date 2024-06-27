package com.kjipo.client;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final String authorizationUri;
    private final String tokenUri;
    private final String clientId;
    private final String clientKey;
    private final String redirectUri;


    public SecurityConfig(@Value("${authorization-uri}") String authorizationUri,
                          @Value("${client-id}") String clientId,
                          @Value("${client-key}") String clientKey,
                          @Value("${token-uri}") String tokenUri,
                          @Value("${redirect-uri}") String redirectUri) {
        this.authorizationUri = authorizationUri;
        this.tokenUri = tokenUri;
        this.clientId = clientId;
        this.clientKey = clientKey;
        this.redirectUri = redirectUri;
    }

    @Order(2)
    @Bean
    public SecurityFilterChain loginEndpoint(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests((requests) ->
                        requests.requestMatchers("/login/**", "/response")
                                .permitAll())
                .build();
    }

    @Order(1)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests((requests) ->
                        requests.anyRequest()
                                .authenticated())
                .oauth2Login(Customizer.withDefaults())
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
//                .redirectUri(redirectUri)
                .redirectUri("{baseUrl}" +OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI)
                // TODO Hardcoded for debugging purposes
                .userInfoUri("http://localhost:8080/login/oauth2/token/auth/userinfo")
//                .userInfoUri("http://localhost:8080/auth/userinfo")
                .userNameAttributeName("user")
                .build();
    }


//    @Bean
//    public OAuth2AuthorizedClientService authorizedClientService() {
//        return new InMemoryOAuth2AuthorizedClientService(
//                clientRegistrationRepository());
//    }


}
