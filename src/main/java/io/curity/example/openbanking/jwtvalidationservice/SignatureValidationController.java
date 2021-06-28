package io.curity.example.openbanking.jwtvalidationservice;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
public class SignatureValidationController {

    String issuerName = "Regulatory Body";
    String jwksUri = "http://localhost:8080/jwks";

    @PostMapping(value = "/validate", consumes = MediaType.TEXT_PLAIN_VALUE)
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void validate(@RequestBody String tokenStr) throws InvalidJwtException {
        // TODO: make configurable
        HttpsJwks httpsJkws = new HttpsJwks(jwksUri);

        // The HttpsJwksVerificationKeyResolver uses JWKs obtained from the HttpsJwks and will select the
        // most appropriate one to use for verification based on the kid and other factors provided
        // in the header of the JWS/JWT.
        HttpsJwksVerificationKeyResolver jwksResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setIssuedAtRestrictions(0,5*60) // JWT must not be older than 5 minutes
                .setExpectedIssuer(issuerName) // name/uri of the authority that issued the token
                .setVerificationKeyResolver(jwksResolver)
                .setJwsAlgorithmConstraints( // restrict the algorithms in the given context
                        AlgorithmConstraints.ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_PSS_USING_SHA256) // only PS256 is allowed here
                .build(); // create the JwtConsumer instance
        jwtConsumer.processToClaims(tokenStr);
    }


    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(InvalidJwtException.class)
    public void invalidJwtExceptionHandler() {
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(JoseException.class)
    public void internalErrorExceptionHandler() {

    }
}
