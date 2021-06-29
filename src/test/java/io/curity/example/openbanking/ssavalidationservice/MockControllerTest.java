package io.curity.example.openbanking.ssavalidationservice;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.security.Key;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = SsaValidationServiceApplication.class)
@WebFluxTest(controllers = MockController.class)
class MockControllerTest {

    @Autowired
    private WebTestClient webClient;

    @Test
    public void getJsonWebKeySet() {
        webClient.get().uri("/jwks").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).consumeWith((data) -> {
                    String jwksStr = data.getResponseBody();
                        try {
                            new JsonWebKeySet(jwksStr);
                        } catch (JoseException e) {
                            Assertions.fail("Returned invalid json web key set.");
                        }
                    });
    }

    @Test
    void getSoftwareStatement() throws JoseException {
        String issuerPublicJwks = "{\"keys\": [" +
            "{" +
                "\"kty\": \"RSA\"," +
                "\"kid\": \"demo-key\"" +
                "\"n\": \"w5lPpKgSsg_HCHCMvaE_XG_FNEoXx2xA_QaUC038RFmHZgKdPBwBWwIZHJZPF8WvOyTBmyHBPqqPy7SOYDdzcYdcbOdu45dRdVy5vxO3RJhz8Nh1HWTgweTl0vUSh_Jc5sPXVQyzJiQotwcQmxixzfde0WPuknyy_KERTx9p-M2sLIaoifpoySODZPpojA470Qj_v8q-vNa6aIcsuHPEShVwvRviPMrRpVpoUkd3tWS6DmL-ywZvEpKhWXdmBbeNpZpLxHRh_MNrTacLP3YxSi_FqPlDRmQg6zEi8SEqb8Q55cd0qS3IOsV7oDlmxvpdIHTbqudh6VEDR4lDeyMpdn581sWcYo8HM8P_IiWFJGNUVOa0iAJZbMOWbcVzKwZxFww9596qkgT-XFd6uLYMSnLOD7zpr1cwavOizaBGL9OjkVbHUD3PSXolZvjyXJli8v-yp6MhDFUBYi9IlXhrkF1ZyZ5FcMFIBHI4yjsAIWx2420FrKhpPrnjP2317xj6c8qKxoSzZdYxQIeCmQGlQOvHhGDkj5Jxur1q2J0MNS0j0n-GWxWQmizATVBwYju3O7BlT6gJoOg34ZlgYaYDRFkuiE2ctEI2coqCbQ-iiA6KHSRU-8xIZ9mggHHtEkX0TSl6oBSN1AQqGcBariRb8v_Z-gHPbq4sUEUgwS-E7RE\"," +
                "\"e\": \"AQAB\"" +
            "}" +
        "]}";

        JsonWebKeySet jwks = new JsonWebKeySet(issuerPublicJwks);
        Key verificationKey = jwks.getJsonWebKeys().get(0).getKey();

        webClient.get().uri("/softwarestatement").exchange()
                .expectStatus().isOk()
                .expectBody(String.class).consumeWith((response) -> {
                    String jwtStr = response.getResponseBody();
                    // Create the Claims, which will be the content of the JWT
                    JwtConsumer consumer = new JwtConsumerBuilder()
                            .setVerificationKey(verificationKey)
                             .build();
            try {
                consumer.processToClaims(jwtStr);
            } catch (InvalidJwtException e) {
                e.printStackTrace();
                Assertions.fail("Invalid software statement created.");
            }
        });
    }

}