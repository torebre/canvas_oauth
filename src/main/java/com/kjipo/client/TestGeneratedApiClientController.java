package com.kjipo.client;


//import org.openapitools.client.ApiException;
//import org.openapitools.client.Configuration;
//import org.openapitools.client.api.UsersApi;
//import org.openapitools.client.model.Profile;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.MediaType;
//import org.springframework.http.ResponseEntity;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
//import org.springframework.stereotype.Controller;
//import org.springframework.web.bind.annotation.GetMapping;
//
//import org.openapitools.client.ApiClient;

/**
 * Uses a generated API client to make calls to the Canvas API.
 */
//@Controller
public class TestGeneratedApiClientController {
//    private final ApiClient apiClient;
//
//
//    private static final Logger log = LoggerFactory.getLogger(TestGeneratedApiClientController.class);
//
//
//    public TestGeneratedApiClientController() {
//        apiClient = Configuration.getDefaultApiClient();
//        apiClient.setBasePath("http://localhost:8080/api");
//    }
//
//
//    /**
//     * <a href="https://docs.spring.io/spring-security/reference/reactive/oauth2/client/authorized-clients.html#oauth2Client-registered-authorized-client">Resolving an Authorized Client</a>
//     *
//     * @param oAuth2AuthorizedClient
//     * @return
//     */
//    @GetMapping(value = "/generatedclient", produces = MediaType.APPLICATION_JSON_VALUE)
//    public ResponseEntity<Profile> callApi(@RegisteredOAuth2AuthorizedClient("canvas") OAuth2AuthorizedClient oAuth2AuthorizedClient, OAuth2AuthenticationToken principal) {
//        String apiKey = oAuth2AuthorizedClient.getAccessToken().getTokenValue();
//        apiClient.setApiKey("Bearer " +apiKey);
//
//        Integer userId = principal.getPrincipal().getAttribute("id");
//        if (userId == null) {
//            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
//        }
//
//        UsersApi usersApi = new UsersApi(apiClient);
//        try {
//            Profile profile = usersApi.getUserProfile(userId.toString());
//
//            return ResponseEntity.ok(profile);
//        } catch (ApiException exception) {
//            log.error("Exception when getting user profile", exception);
//
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
//        }
//    }

}
