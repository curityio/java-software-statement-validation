package io.curity.example.openbanking.jwtvalidationservice;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Controller
public class MockController {

    String issuerJwk = "{" +
            "\"kty\": \"RSA\"," +
            "\"kid\": \"demo-key\"" +
            "\"n\": \"w5lPpKgSsg_HCHCMvaE_XG_FNEoXx2xA_QaUC038RFmHZgKdPBwBWwIZHJZPF8WvOyTBmyHBPqqPy7SOYDdzcYdcbOdu45dRdVy5vxO3RJhz8Nh1HWTgweTl0vUSh_Jc5sPXVQyzJiQotwcQmxixzfde0WPuknyy_KERTx9p-M2sLIaoifpoySODZPpojA470Qj_v8q-vNa6aIcsuHPEShVwvRviPMrRpVpoUkd3tWS6DmL-ywZvEpKhWXdmBbeNpZpLxHRh_MNrTacLP3YxSi_FqPlDRmQg6zEi8SEqb8Q55cd0qS3IOsV7oDlmxvpdIHTbqudh6VEDR4lDeyMpdn581sWcYo8HM8P_IiWFJGNUVOa0iAJZbMOWbcVzKwZxFww9596qkgT-XFd6uLYMSnLOD7zpr1cwavOizaBGL9OjkVbHUD3PSXolZvjyXJli8v-yp6MhDFUBYi9IlXhrkF1ZyZ5FcMFIBHI4yjsAIWx2420FrKhpPrnjP2317xj6c8qKxoSzZdYxQIeCmQGlQOvHhGDkj5Jxur1q2J0MNS0j0n-GWxWQmizATVBwYju3O7BlT6gJoOg34ZlgYaYDRFkuiE2ctEI2coqCbQ-iiA6KHSRU-8xIZ9mggHHtEkX0TSl6oBSN1AQqGcBariRb8v_Z-gHPbq4sUEUgwS-E7RE\"," +
            "\"e\": \"AQAB\"," +
            "\"d\": \"vcaoEVfJG95W_AdHZk1mzmbbbUpeG-0aeOTDCtzVX_OFfSIYMFPztLsqZiQoBSaWR8n31m4_sm-GKNy8LvpeFc6BjGBXpJYSQM6AobWdYP6RryI1LxnLQBS4L5_8JM6v-G4XJLu3rc_zePFv2StyiCX0ZzCQLqyydI5J3vzZsr7KyEC2kXjV5iGAwJ58hTbiLoSOryUlPs8P-Y79gtE_p6l5wuGk9drK4aYABaS1rtdV9dNy5sUNS3Xc-pLv96gJ1J0J2kgZMkbge20RardgR1xmaPW_ojJQBiGch1vocpxumFSXCfYTiYJF2kUXRQNxC6aV4xGwW9FwXx38zSJmfI6JxCqB3udPzzTHPHkCZ7yahYHsgJTNX-jpVnQLpf8FY27ra2MK2f1voYPzPJbp_9WtCqdvmB8kVcyRbJEkboiZcoPBgihrbTbl2taeYQ3IrbgMfBaw69m_0aqRuRjutwdYpJDsPEhE32KruTgvZRd8vLi8L3MLxBPFv4TPTU2wQozGmZSesHQ4fy3NfarweFAKqW3syI2e5HXGEGr15R9KGPRrZTGx3cnGA0F2bPMlXIqAMfjCteaSDjylEq1oHkAs1SWNJfHKYAzNgspisztzbLHXCVf5MRJaQpd3rNIbV6_sCWV3toayhMxTXEqR5PYlA71k4pch3ItWkCLhRuE\"," +
            "\"p\": \"-eB9J-vpB4QETrCD0DB-V_bZqZnMnMhA9GYzpqSf58vkjeooDKJGKKI4ghnsBy_RBT6-04rULjetFnbmYhYEisL5-T7myGT2RuHsfQFnl2X_hKkdKPdwZvNTYQKrTcqnX9ThlIso_mQZVqo6rdpZ7rfmu-jmBaymHfUl3ZigeuaCDa2B6pk4LeVMCyVv2XILdPcFIc3R4xgUvUI6xal7xfjUYjTP9F0bUxSLxdCQs3_v99gyyHcUGJvNjeO_m8ylC8IqymNPYTT-wEFRUE0mgwIRNQ7sRKf7k60lKyEpEjk5Do6z7IFh8rbkyJvIF6JQWN1POxPEargSaVciUPjHhQ\"," +
            "\"q\": \"yGRUMBFuqY3FlDef70h0alKHtab1AyFnwYbrGYIUpYtdQ9E3NwVOCq9i_Nq_CL6KrUXAOMNbIP-MyGiF29PxGJz5MYEDLmv4Fu6aO0tPk7UxYdNLIG8e3sgMG1NznO2-SCOhJjBFT7mGifZu4FjptYHnMeTSO9ms_aSSMKNRzVhtI849yPTN5fjLpPfHcXcltlE8Z1kxYj7iCtd3hHCY_yNbt8vhYRcW_vPwV6PHSJRAFhCwpkFFBX6Se-WSC-i-bj0_SJRkiXZL-c29XoqbW8F5OHXOBaGw4wytMxeNFDr4fU2WyDt8Y6haSziWW8WP-Ka-ZciOecWJbCxTPxH3HQ\"," +
            "\"dp\": \"QQD2biE_8PWWDUZ8M_e5lnagLy_Ue-DYjPvdafefpbR0E7sbihXY_I8e9jF6JnB5Bs1I5U1TX2aaf6KU0mV57wND9mQ3s2AYdV4moGpyIX-mVkOMU3Dza8TXJwCDwev7WMHPoU4Gbw9pTBNiyoFoLeLngnDXDhjY6igxHpGrBe3bXWWKy5XqeH4TJz8o9r9lXZs5WY7qkBJeqtGE6pDpoxnVXmrwwlhKWHWa2u4kBp48thQnOeFIeBJoCgZ6fTRip0luylHFf7tCno8fcS1w3Fn4Uf481quAle1QIwUwYw5B2pijE96gtXyAzfNAvW07S7Le_rZovX5_Q6ooQjpF5Q\"," +
            "\"dq\": \"NMN2B1IPuUVDCMu8qNyDCpvAb-wOB0z8bNCBhq3hkdUoMXsc9rfG3LlhbwKJ2luRWB5NhqSpkf63qu0akc80ZC6wzoARvl9fa2pX4dTqlxHWdtOTrG6VykMSLP_EKUXQHF6FR_DdzygibKEegKPopYoWveRqFqgyDHcQpw3ZtB_cXNkpG4iZzju8Iyu6r_2XSHILXYr2nc_A5Onm5lBfeI5uz-424cGapHbGiczt5AZk-WpbmOsGqXOyTj0cP1aBDbXCu_GWpzsmtheeDQ6h6X7_1AXwwTrZwG7OC-3fj7wXQab0VLSVBAiH_dZggLl8NxRwfYxZN2bz0C-7m5e3YQ\"," +
            "\"qi\": \"3YtMOKBpyh8BZnrhcGOPfYmlL-4jePx9TrFq_HvNHOXDtOTeqZDjkU_j4Crvr9jIdjLMKUGezrnuW-Ff37-lkZxlV5u0jdoxJRORb0uQ1e1zNQRm1L1wLi_hPhNCaOSrp6TCyoBHMlik9qH9XfapLXaxP6HLP9BbCAo8-GIDgea9_PrpJfaJFcA3AuAhfludl0TPYWDHaTIECXENo7_cQqb1c9OeYuuL4qmEqeUMTJuyxd23XLFuE6LdEYdmC0xQqJHvVIRYqAe_YIzsYlYcFdD4zvAId-AI2tP7HFrVkAmnyIK5X7lrjXt4Gb8sftqq7JOCEnd8dDm2cxcSYz1iYg\"" +
            "}";

    // Mock jwks endpoint
    @GetMapping(value = "/jwks", produces = "application/jwk-set+json")
    public ResponseEntity<Mono<String>> getJsonWebKeySet() {
        //Demo test key
        String issuerPublicJwks = "{\"keys\": [" +
                "{" +
                "\"kty\": \"RSA\"," +
                "\"kid\": \"demo-key\"" +
                "\"n\": \"w5lPpKgSsg_HCHCMvaE_XG_FNEoXx2xA_QaUC038RFmHZgKdPBwBWwIZHJZPF8WvOyTBmyHBPqqPy7SOYDdzcYdcbOdu45dRdVy5vxO3RJhz8Nh1HWTgweTl0vUSh_Jc5sPXVQyzJiQotwcQmxixzfde0WPuknyy_KERTx9p-M2sLIaoifpoySODZPpojA470Qj_v8q-vNa6aIcsuHPEShVwvRviPMrRpVpoUkd3tWS6DmL-ywZvEpKhWXdmBbeNpZpLxHRh_MNrTacLP3YxSi_FqPlDRmQg6zEi8SEqb8Q55cd0qS3IOsV7oDlmxvpdIHTbqudh6VEDR4lDeyMpdn581sWcYo8HM8P_IiWFJGNUVOa0iAJZbMOWbcVzKwZxFww9596qkgT-XFd6uLYMSnLOD7zpr1cwavOizaBGL9OjkVbHUD3PSXolZvjyXJli8v-yp6MhDFUBYi9IlXhrkF1ZyZ5FcMFIBHI4yjsAIWx2420FrKhpPrnjP2317xj6c8qKxoSzZdYxQIeCmQGlQOvHhGDkj5Jxur1q2J0MNS0j0n-GWxWQmizATVBwYju3O7BlT6gJoOg34ZlgYaYDRFkuiE2ctEI2coqCbQ-iiA6KHSRU-8xIZ9mggHHtEkX0TSl6oBSN1AQqGcBariRb8v_Z-gHPbq4sUEUgwS-E7RE\"," +
                "\"e\": \"AQAB\"" +
                "}" +
                "]}";
        return ResponseEntity.ok(Mono.just(issuerPublicJwks));
    }

    // Mock software statement
    @GetMapping(value = "/softwarestatement", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Mono<String>> getJwt() throws JoseException {
        UUID softwareId = UUID.randomUUID();
        UUID orgId = UUID.randomUUID();

        // Set some claims
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("Regulatory Body");
        claims.setIssuedAtToNow();
        claims.setStringClaim("software_id", softwareId.toString());
        claims.setStringClaim("software_client_id", "JNA9r-duS4uCzL89z");
        claims.setStringClaim("software_client_uri", "https://tpp.example.com");
        claims.setStringClaim("software_logo_uri", "https://example.com/images/logo.png");
        claims.setStringClaim("software_tos_uri", "https://example.com/termsofservices");
        claims.setStringClaim("software_policy_uri", "https://example.com/policy");
        claims.setStringListClaim("software_redirect_uris", "https://tpp.example.com/","https://example.com/callback");
        claims.setStringClaim("software_jwks_uri", String.format("https://keystore.regulatory.body/%s/%s/application.jwks", orgId, softwareId));
        claims.setStringClaim("software_environment", "Test");
        claims.setClaim("software_version", 0.1);
        claims.setStringListClaim("software_roles", "Role1", "Role2");
        claims.setClaim("org_id", orgId);
        claims.setClaim("org_number", "1871679847");
        claims.setClaim("org_name", "Test Company");

        JsonWebSignature jws = new JsonWebSignature();

        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // Load signing key
        JsonWebKey signingKey = JsonWebKey.Factory.newJwk(issuerJwk);
        jws.setKey(((PublicJsonWebKey)signingKey).getPrivateKey());

        // Prepare header
        jws.setAlgorithmHeaderValue("PS256");
        jws.setKeyIdHeaderValue(signingKey.getKeyId());

        // Sign and encode JWT
        String jwt = jws.getCompactSerialization();
        return ResponseEntity.ok(Mono.just(jwt));
    }
}
