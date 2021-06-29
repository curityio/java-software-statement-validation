package io.curity.example.openbanking.ssavalidationservice;

import org.jose4j.jwk.HttpsJwks;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SsaValidationServiceApplication {

    @Value("${jwt.issuer.jwks_uri:http://localhost:8080/jwks}")
    private String jwksUri;

    public static void main(String[] args) {
        SpringApplication.run(SsaValidationServiceApplication.class, args);
    }

    @Bean
    public HttpsJwks getHttpsJwks() {
        return new HttpsJwks(jwksUri);
    }
}
