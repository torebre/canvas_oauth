package com.kjipo.client;


import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestClient;

@Controller
public class TestApiController {

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
