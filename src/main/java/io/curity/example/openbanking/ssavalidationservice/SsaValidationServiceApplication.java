package io.curity.example.openbanking.ssavalidationservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(
        exclude = { SecurityAutoConfiguration.class })
public class SsaValidationServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsaValidationServiceApplication.class, args);
    }

}
