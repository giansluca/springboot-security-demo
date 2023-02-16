package org.gmdev.securitydemo.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;

@Configuration
public class JwtConfig {

    private final String secretKey;
    private final String tokenPrefix;
    private final Integer tokenExpirationMinutes;

    public JwtConfig(
            @Value("${application.jwt.secretKey:null}") String secretKey,
            @Value("${application.jwt.tokenPrefix:null}") String tokenPrefix,
            @Value("${application.jwt.tokenExpirationMinutes:null}")Integer tokenExpirationMinutes) {

        this.secretKey = secretKey;
        this.tokenPrefix = tokenPrefix;
        this.tokenExpirationMinutes = tokenExpirationMinutes;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public Integer getTokenExpirationMinutes() {
        return tokenExpirationMinutes;
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }

}
