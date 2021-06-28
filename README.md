# JWT Validation with Java

[![Quality](https://img.shields.io/badge/quality-experiment-red.svg)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)
 

## Overview

This example shows how to validate a jwt with java using [jose4j](https://bitbucket.org/b_c/jose4j). A simple service is created that accepts a JWT, loads the verification key from a JWKS endpoint and validates the signature of the token. In addition, the example also checks that `PS256` (RSASSA-PSS) was used to generate the signature and that the JWT does not exceed the lifetime of 5 minutes. Such requirements are, for example, part of the software statement defined in [Open Banking Brasil Financial-grade API Dynamic Client Registration Profile 1.0](https://github.com/OpenBanking-Brasil/specs-seguranca).

To enable quick testing two mocking endpoints have been added: `/jwks` for the public keys of the "Regulatory Body" that issues the JWT at `/softwarestatement`. In the Open Banking scenario a regulatory authority will issue the software statement out of band and publish its keys in form of a JWKS file at a secure endpoint. Just change the values for `jwt.issuer.jwks_uri` and `jwt.issuer` to adapt the example for a different authority.

## Running the JWT Validation Service

Start the service with the following command:

```shell
./mvnw spring-boot:run
```
The service is listening on port 8080.

Retrieve a software statement for testing:

```shell
curl http://localhost:8080/softwarestatement > softwarestatement.txt
```

Validate the token:

```shell
curl -X POST -H "Content-Type: text/plain" -d @softwarestatement.txt http://localhost:8080/validate -v
```

The token is valid if the server returns `HTTP/1.1 204 No Content`.

To change the issuer export environment variables with the corresponding values before starting the service:

```shell
export jwt_issuer="Authority"
export jwt_issuer_jwks_uri="https://some-very-trusted-server/authority.jwks"
./mvn spring-boot:run
```

## More Information
This example implements a simple, reactive web service using Spring Boot. Check out [the reference documentation for WebFlux](https://spring.getdocs.org/en-US/spring-framework-docs/docs/spring-web-reactive/webflux/webflux.html) for further details.
 
Since the goal is to show how to implement JWT validation without the overhead of a full OAuth 2.0 or OpenID Connect flow, this example uses [jose4j](https://bitbucket.org/b_c/jose4j) for parsing and validating the token. For information about how to protect an API with access tokens using OAuth 2.0 or OpenID Connect in Spring Boot checkout [OAuth 2.0 for WebFlux (Spring Security)](https://docs.spring.io/spring-security/site/docs/current/reference/html5/#webflux-oauth2-resource-server) and have a look at the example [Securing a Spring Boot API with JWTs](https://curity.io/resources/learn/spring-boot-api/).

## Licensing

This software is copyright (C) 2021 Curity AB. It is open source software that is licensed under the [Apache 2](LICENSE).