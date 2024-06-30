package com.kjipo.client;


import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestClient;

@Controller
public class TestApiController {


    /**
     * <a href="https://docs.spring.io/spring-security/reference/reactive/oauth2/client/authorized-clients.html#oauth2Client-registered-authorized-client">Resolving an Authorized Client</a>
     *
     * @param oAuth2AuthorizedClient
     * @return
     */
    @GetMapping("/callapi")
    public ResponseEntity<String> callApi(@RegisteredOAuth2AuthorizedClient("canvas") OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        RestClient client = RestClient.create();

        String response = client.get().uri("http://localhost:8080/api/v1/users/self")
                .header("Authorization", "Bearer " + oAuth2AuthorizedClient.getAccessToken().getTokenValue())
                .retrieve()
                .body(String.class);

        return ResponseEntity.ok(response);
    }

}
