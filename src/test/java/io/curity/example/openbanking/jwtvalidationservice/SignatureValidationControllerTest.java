package io.curity.example.openbanking.jwtvalidationservice;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.BodyInserters;

import java.security.Key;
import java.time.Clock;
import java.time.Instant;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = JwtValidationServiceApplication.class)
@WebFluxTest(controllers = SignatureValidationController.class)
public class SignatureValidationControllerTest {

    @Autowired
    private WebTestClient webClient;

    private static String issuerJwks = "{" +
            "\"keys\": [" +
                "{"+
                    "\"kty\": \"RSA\"," +
                    "\"kid\": \"demo-key\"" +
                    "\"n\": \"w5lPpKgSsg_HCHCMvaE_XG_FNEoXx2xA_QaUC038RFmHZgKdPBwBWwIZHJZPF8WvOyTBmyHBPqqPy7SOYDdzcYdcbOdu45dRdVy5vxO3RJhz8Nh1HWTgweTl0vUSh_Jc5sPXVQyzJiQotwcQmxixzfde0WPuknyy_KERTx9p-M2sLIaoifpoySODZPpojA470Qj_v8q-vNa6aIcsuHPEShVwvRviPMrRpVpoUkd3tWS6DmL-ywZvEpKhWXdmBbeNpZpLxHRh_MNrTacLP3YxSi_FqPlDRmQg6zEi8SEqb8Q55cd0qS3IOsV7oDlmxvpdIHTbqudh6VEDR4lDeyMpdn581sWcYo8HM8P_IiWFJGNUVOa0iAJZbMOWbcVzKwZxFww9596qkgT-XFd6uLYMSnLOD7zpr1cwavOizaBGL9OjkVbHUD3PSXolZvjyXJli8v-yp6MhDFUBYi9IlXhrkF1ZyZ5FcMFIBHI4yjsAIWx2420FrKhpPrnjP2317xj6c8qKxoSzZdYxQIeCmQGlQOvHhGDkj5Jxur1q2J0MNS0j0n-GWxWQmizATVBwYju3O7BlT6gJoOg34ZlgYaYDRFkuiE2ctEI2coqCbQ-iiA6KHSRU-8xIZ9mggHHtEkX0TSl6oBSN1AQqGcBariRb8v_Z-gHPbq4sUEUgwS-E7RE\"," +
                    "\"e\": \"AQAB\"," +
                    "\"d\": \"vcaoEVfJG95W_AdHZk1mzmbbbUpeG-0aeOTDCtzVX_OFfSIYMFPztLsqZiQoBSaWR8n31m4_sm-GKNy8LvpeFc6BjGBXpJYSQM6AobWdYP6RryI1LxnLQBS4L5_8JM6v-G4XJLu3rc_zePFv2StyiCX0ZzCQLqyydI5J3vzZsr7KyEC2kXjV5iGAwJ58hTbiLoSOryUlPs8P-Y79gtE_p6l5wuGk9drK4aYABaS1rtdV9dNy5sUNS3Xc-pLv96gJ1J0J2kgZMkbge20RardgR1xmaPW_ojJQBiGch1vocpxumFSXCfYTiYJF2kUXRQNxC6aV4xGwW9FwXx38zSJmfI6JxCqB3udPzzTHPHkCZ7yahYHsgJTNX-jpVnQLpf8FY27ra2MK2f1voYPzPJbp_9WtCqdvmB8kVcyRbJEkboiZcoPBgihrbTbl2taeYQ3IrbgMfBaw69m_0aqRuRjutwdYpJDsPEhE32KruTgvZRd8vLi8L3MLxBPFv4TPTU2wQozGmZSesHQ4fy3NfarweFAKqW3syI2e5HXGEGr15R9KGPRrZTGx3cnGA0F2bPMlXIqAMfjCteaSDjylEq1oHkAs1SWNJfHKYAzNgspisztzbLHXCVf5MRJaQpd3rNIbV6_sCWV3toayhMxTXEqR5PYlA71k4pch3ItWkCLhRuE\"," +
                    "\"p\": \"-eB9J-vpB4QETrCD0DB-V_bZqZnMnMhA9GYzpqSf58vkjeooDKJGKKI4ghnsBy_RBT6-04rULjetFnbmYhYEisL5-T7myGT2RuHsfQFnl2X_hKkdKPdwZvNTYQKrTcqnX9ThlIso_mQZVqo6rdpZ7rfmu-jmBaymHfUl3ZigeuaCDa2B6pk4LeVMCyVv2XILdPcFIc3R4xgUvUI6xal7xfjUYjTP9F0bUxSLxdCQs3_v99gyyHcUGJvNjeO_m8ylC8IqymNPYTT-wEFRUE0mgwIRNQ7sRKf7k60lKyEpEjk5Do6z7IFh8rbkyJvIF6JQWN1POxPEargSaVciUPjHhQ\"," +
                    "\"q\": \"yGRUMBFuqY3FlDef70h0alKHtab1AyFnwYbrGYIUpYtdQ9E3NwVOCq9i_Nq_CL6KrUXAOMNbIP-MyGiF29PxGJz5MYEDLmv4Fu6aO0tPk7UxYdNLIG8e3sgMG1NznO2-SCOhJjBFT7mGifZu4FjptYHnMeTSO9ms_aSSMKNRzVhtI849yPTN5fjLpPfHcXcltlE8Z1kxYj7iCtd3hHCY_yNbt8vhYRcW_vPwV6PHSJRAFhCwpkFFBX6Se-WSC-i-bj0_SJRkiXZL-c29XoqbW8F5OHXOBaGw4wytMxeNFDr4fU2WyDt8Y6haSziWW8WP-Ka-ZciOecWJbCxTPxH3HQ\"," +
                    "\"dp\": \"QQD2biE_8PWWDUZ8M_e5lnagLy_Ue-DYjPvdafefpbR0E7sbihXY_I8e9jF6JnB5Bs1I5U1TX2aaf6KU0mV57wND9mQ3s2AYdV4moGpyIX-mVkOMU3Dza8TXJwCDwev7WMHPoU4Gbw9pTBNiyoFoLeLngnDXDhjY6igxHpGrBe3bXWWKy5XqeH4TJz8o9r9lXZs5WY7qkBJeqtGE6pDpoxnVXmrwwlhKWHWa2u4kBp48thQnOeFIeBJoCgZ6fTRip0luylHFf7tCno8fcS1w3Fn4Uf481quAle1QIwUwYw5B2pijE96gtXyAzfNAvW07S7Le_rZovX5_Q6ooQjpF5Q\"," +
                    "\"dq\": \"NMN2B1IPuUVDCMu8qNyDCpvAb-wOB0z8bNCBhq3hkdUoMXsc9rfG3LlhbwKJ2luRWB5NhqSpkf63qu0akc80ZC6wzoARvl9fa2pX4dTqlxHWdtOTrG6VykMSLP_EKUXQHF6FR_DdzygibKEegKPopYoWveRqFqgyDHcQpw3ZtB_cXNkpG4iZzju8Iyu6r_2XSHILXYr2nc_A5Onm5lBfeI5uz-424cGapHbGiczt5AZk-WpbmOsGqXOyTj0cP1aBDbXCu_GWpzsmtheeDQ6h6X7_1AXwwTrZwG7OC-3fj7wXQab0VLSVBAiH_dZggLl8NxRwfYxZN2bz0C-7m5e3YQ\"," +
                    "\"qi\": \"3YtMOKBpyh8BZnrhcGOPfYmlL-4jePx9TrFq_HvNHOXDtOTeqZDjkU_j4Crvr9jIdjLMKUGezrnuW-Ff37-lkZxlV5u0jdoxJRORb0uQ1e1zNQRm1L1wLi_hPhNCaOSrp6TCyoBHMlik9qH9XfapLXaxP6HLP9BbCAo8-GIDgea9_PrpJfaJFcA3AuAhfludl0TPYWDHaTIECXENo7_cQqb1c9OeYuuL4qmEqeUMTJuyxd23XLFuE6LdEYdmC0xQqJHvVIRYqAe_YIzsYlYcFdD4zvAId-AI2tP7HFrVkAmnyIK5X7lrjXt4Gb8sftqq7JOCEnd8dDm2cxcSYz1iYg\"," +
                "}," +
                "{" +
                    "\"kty\": \"RSA\"," +
                    "\"kid\": \"unknown-key\"," +
                    "\"alg\": \"RS256\"," +
                    "\"n\": \"t1-5Q67vWwGHQxHXYU10kVcwF-rsZn5hDe9jN7ZKCSkjNxbofMtdfpe8xiMa7PNawxQsfxh7EmRtdfKTifksSLjEC4Q4pIk6sUqkL3b0uiIVORzX44CMCZx91-W6E_j3UKkKQv4fLr0J_3lOesscMFKwAJeD2_UvNWb6PPvPruAYy2Is0MBJIHC9V34bKoPX1up770eE_f6NtXsvCGtLVTsvXXsTC3R5cRe6X5kqD22G2-Y0K-vZCxRuLzqVnSWcb01Eyz7OjpIHY3BJA8MrEIxsVHXozyGebZITMzqWcRfeVm3B8C7hB4FH3Bn1G7lZ4RUdtZ9_qleRyxCyerZxYw\"," +
                    "\"e\": \"AQAB\"," +
                    "\"d\": \"pDDQ2Pq1FP6MV5CNEnHhExZHWNMf8zHrwyd65nKRXhx4jKY1azBIucYx4BOk00-fEBdrNC3-XNyRak_WrW7vqPnPiCRO93xskjysQFe6D0PfTvE1mV4LhbuarorjD2kYQR_qsUuLLjVT022RyL8-sUIIl68TAQtLxvw6ygoKzqASXWon1cfJP0QspX-yxOqykOJJjR_l_wS9_TDA8mhAgODg-6aMfjjgIxZqLA8aRyH5V1-M6riTV5lhGRG4zPjE8Ps4lhAuNCflWYcNl_ywVVcx_5Tqho8uL1Aa8u32D8gmVR1cVhHzGnQNOTui9JWwEOO08G9vx9ClHNPa-2KkwQ\"," +
                    "\"p\": \"6XVvec_FieuYEFg58LvCFubL3pDpg9rj9sUCr3QV6Exyu51qNuEDoDVfe4bv2CFzoJwm4ezxJBN7cfXpmwnVS_a3fg6uwySxvwe6jSDbzIAtn2PDNhBTxVT_a7ZBOoMwTl8ChAmvfUsn_V5tssVltmnR2nJsfbvWTAJS1_QqPUM\"," +
                    "\"q\": \"yRROeTnppT-4brE8X38LblbBCkCRoos7GFeaXUjY3K397L5sV64MmpZA9EiYVKn1TtO4yymFpVFgS4L7xQfUxWXSKRkkTQ9g5dLI1S4rhAVWVe9EejepYwQ5faseC0Mb5k4R0xgTtR9BneFVAcQOPqGaPFamer9iC65uXBRsqWE\"," +
                    "\"dp\": \"FQyemXgPUokoc8jQqJD1RgVXOmEMfPP-e-B1hoZL9171NU9TJVGSdx541nVrKKyTdVa-9r3bXCpZhgPrJSx0y92Z28bNIREs6ZFz04ez6bNg6a8gCb7dHry0Lu0G4pSzhU1xt5_776sYFvMtpuG_cvwFjNGmUIvgHYhUGd6M9Gs\"," +
                    "\"dq\": \"i1qKZBNRrJdzjys_pwMZ_fcbw6oqBBcv9lfIADxbJt1ibG8wELfrvjrBe0rQX2SGQIIUwJ_fIko6TTrSl6Msvz0ooBjvgoRU6BHj43Ii8FTul5HByF3JA3lLCp_Lq4xvynVyfvRhvBWUWQFv81BXeupuRMDckZcPMP9LNn9lKyE\"," +
                    "\"qi\": \"ezuFFjMJLFW7ssJe_pL0QXGrBYB-cP2aQgWmt13N40vHATVt1lLV0DcHlKkdl5iGdETDJVNSpD3E5evxWqiWcxLQcnSC7sbHzjODvuVvuL2YU1SqGAe7dt3_dqNEXU2FyRX87KQ65g7mR08HoogFPRq78QewOjJyKc8WPcGR8kA\"," +
                "}" +
            "]}";

    private static String jwtSsa = "eyJraWQiOiJzaWduZXIiLCJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJSZWd1bGF0b3J5IEJvZHkiLCJpYXQiOjE2NTU4MzUyODIsInNvZnR3YXJlX2lkIjoiZDA3NTU0ODktNGQ4YS00ZWZkLWFlZDAtN2RhMmJkM2Y4ZWRjIiwic29mdHdhcmVfY2xpZW50X2lkIjoiSk5BOXItZHVTNHVDekw4OXoiLCJzb2Z0d2FyZV9jbGllbnRfbmFtZSI6IlRlc3QgQ2xpZW50IDEiLCJzb2Z0d2FyZV9jbGllbnRfdXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3QvdGVzdGNsaWVudCIsInNvZnR3YXJlX2xvZ29fdXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3QiLCJzb2Z0d2FyZV90b3NfdXJpIjoiaHR0cHM6Ly9sb2NhbGhvc3QvdG9zIiwic29mdHdhcmVfcG9saWN5X3VyaSI6Imh0dHBzOi8vbG9jYWxob3N0L3BvbGljeSIsInNvZnR3YXJlX3JlZGlyZWN0X3VyaXMiOlsiaHR0cHM6Ly90cHAubG9jYWxob3N0L2NiIiwiaHR0cHM6Ly9sb2NhbGhvc3Q6ODQ0My90ZXN0L2NhbGxiYWNrIl0sInNvZnR3YXJlX2p3a3NfdXJpIjoiaHR0cHM6Ly9rZXlzdG9yZS5yZWd1bGF0b3J5LmJvZHkvYzZmNjk5N2MtMDc5ZC00ZmRjLTllZDctOWE2YjM0NTdhOTQyL2QwNzU1NDg5LTRkOGEtNGVmZC1hZWQwLTdkYTJiZDNmOGVkYy9hcHBsaWNhdGlvbi5qd2tzIiwic29mdHdhcmVfZW52aXJvbm1lbnQiOiJUZXN0Iiwic29mdHdhcmVfdmVyc2lvbiI6IjAuMTAiLCJzb2Z0d2FyZV9yb2xlcyI6WyJSb2xlMSIsIlJvbGUyIl0sIm9yZ19pZCI6ImM2ZjY5OTdjLTA3OWQtNGZkYy05ZWQ3LTlhNmIzNDU3YTk0MiIsIm9yZ19udW1iZXIiOiIxODcxNjc5ODQ3Iiwib3JnX25hbWUiOiJUZXN0aW5nIENvbXBhbnkifQ.DhuSG2Mdaekh1S0kvSiTVsfHiO20SUaUG3iTe16OnCNV1clLb7qSyI0AodTbfOzYKgELEdopz1cKSFDsmXb6kdF6n5CgDFGhU0P2oPMXM4GwnMGXwIyzsnzuNmESN0uZo8QngeA3WJs1Dr6nPXt_jubbttRrCYfGninxkrhWOT09UZOnADZ96j-9N-_wWs3gF6ZMaoWiDtXKDnWG7WSYbMSP1O91pcIQfud_0NHEC-s1qhtbUK1jCPfSk4DPoMdFEBiBxl8ED-fBk7I1NoepohtPgdReFrOEItwZFO7SdZlh75MaEgCXnfzsgi8tSJwUS7LF6-wUaSrNVYtpmO7iR35AT3qlTHU3KgtHKRTZ4Z48zPRK1dNOCCVGjf-Juv-TTz8t70piTIJrIMLOqnwsLdIuZzR1Ld5OrVv3AobNHSD2-eej1DHS3-Ed9dojiirb3VR07PyFucjMxHpNxZo4t6Epp27kmAMARjaxv7R7n9p7QoaOoq0tAIXxkBRpkKV_uOqluEF_S0hBSB1Jlo3mSM6GhGD6ZBqXuBsjwnqn9MnPcE-qQbTwCm2c-RFNvsQnbZSPAweBh8ADnYYzrVjgg9PnKwn4Q5se2g6YmZZFd2hXzl4mR_VILEVpEjfiPFgXD7EIeP0Gs6lIuMYTEqgTVrn94rzqtUEE_IYQbtk5Ink";

    @Test
    public void getJwks() {
        webClient.get().uri("/jwks").exchange().expectStatus().isOk();
    }
    @Test
    public void validateJwt() throws InvalidJwtException, JoseException {
        String validJwt = createJwt("Regulatory Body", "demo-key", Instant.now(Clock.systemUTC()), AlgorithmIdentifiers.RSA_PSS_USING_SHA256);

        webClient.post()
                .uri("/validate")
                .contentType(MediaType.TEXT_PLAIN)
                .body(BodyInserters.fromValue(validJwt))
                .exchange()
                .expectStatus().isNoContent();
    }

    @Test
    public void rejectOldJwt() {
        webClient.post()
                .uri("/validate")
                .contentType(MediaType.TEXT_PLAIN)
                .body(BodyInserters.fromValue(jwtSsa))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    public void unknownIssuer() throws InvalidJwtException, JoseException {
        String jwtByInvalidIssuer = createJwt("Some other authority", "demo-key", Instant.now(Clock.systemUTC()), AlgorithmIdentifiers.RSA_PSS_USING_SHA256);

        webClient.post()
                .uri("/validate")
                .contentType(MediaType.TEXT_PLAIN)
                .body(BodyInserters.fromValue(jwtByInvalidIssuer))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    public void unknownKid() throws InvalidJwtException, JoseException {
        String jwtByUnknownKey = createJwt("Regulatory Body", "unknown-key", Instant.now(Clock.systemUTC()), AlgorithmIdentifiers.RSA_PSS_USING_SHA256);

        webClient.post()
                .uri("/validate")
                .contentType(MediaType.TEXT_PLAIN)
                .body(BodyInserters.fromValue(jwtByUnknownKey))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    public void invalidAlgorithm() throws InvalidJwtException, JoseException {
        String jwtWithInvalidAlg = createJwt("Regulatory Body", "demo-key", Instant.now(Clock.systemUTC()), AlgorithmIdentifiers.RSA_USING_SHA256);

        webClient.post()
                .uri("/validate")
                .contentType(MediaType.TEXT_PLAIN)
                .body(BodyInserters.fromValue(jwtWithInvalidAlg))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    public void futureJwt() throws InvalidJwtException, JoseException {
        String jwtByInvalidIssuer = createJwt("Regulatory Body", "demo-key", Instant.now(Clock.systemUTC()).plusSeconds(300), AlgorithmIdentifiers.RSA_PSS_USING_SHA256);

        webClient.post()
                .uri("/validate")
                .contentType(MediaType.TEXT_PLAIN)
                .body(BodyInserters.fromValue(jwtByInvalidIssuer))
                .exchange()
                .expectStatus().isBadRequest();
    }

    @Test
    public void invalidContentType() throws InvalidJwtException, JoseException {
        String validJwt = createJwt("Regulatory Body", "demo-key", Instant.now(Clock.systemUTC()), AlgorithmIdentifiers.RSA_PSS_USING_SHA256);

        webClient.post()
                .uri("/validate")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromValue(validJwt))
                .exchange()
                .expectStatus().is4xxClientError();
    }

    //https://bitbucket.org/b_c/jose4j/wiki/Home
    private static String createJwt(String issuer, String kid, Instant iat, String algorithm) throws InvalidJwtException, JoseException {

        // Create the Claims, which will be the content of the JWT
        JwtConsumer consumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        //Load claims from old JWT
        JwtClaims claims = consumer.processToClaims(jwtSsa);

        //Update claims
        claims.setIssuer(issuer);
        NumericDate iatDate = NumericDate.fromMilliseconds(iat.toEpochMilli());
        claims.setIssuedAt(iatDate);

        JsonWebSignature jws = new JsonWebSignature();

        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // Use the key identified by the kid
        Key signingKey = getKey(kid);
        jws.setKey(signingKey);

        jws.setAlgorithmHeaderValue(algorithm);
        jws.setKeyIdHeaderValue(kid);

        String jwt = jws.getCompactSerialization();
        return jwt;
    }

    // Retrieve key with kid from json web key set
    static private Key getKey(String kid) throws JoseException {
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(issuerJwks);
        JsonWebKey jwk = jsonWebKeySet.findJsonWebKey(kid, null, null, null);
        if (jwk instanceof PublicJsonWebKey) {
            return ((PublicJsonWebKey) jwk).getPrivateKey();
        } else {
            return jwk.getKey();
        }
    }
}
