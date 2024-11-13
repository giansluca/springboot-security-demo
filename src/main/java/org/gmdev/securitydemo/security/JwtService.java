package org.gmdev.securitydemo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.Date;

@Configuration
public class JwtService {

    private static final String BEARER = "Bearer ";

    private final String secretKey;
    private final Integer tokenExpirationMinutes;
    @Getter
    private final String tokenPrefix;

    public JwtService(
            @Value("${application.jwt.secretKey:null}") String secretKey,
            @Value("${application.jwt.tokenExpirationMinutes:null}") Integer tokenExpirationMinutes) {

        this.secretKey = secretKey;
        this.tokenExpirationMinutes = tokenExpirationMinutes;
        this.tokenPrefix = BEARER;
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }

    public SecretKey secretKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generateBearerToken(UserDetails userDetails) {
        String token = generateToken(userDetails);
        return String.format("%s%s", BEARER, token);
    }

    public String extractUsername(String token) {
        Claims claims = extractClaims(token);
        return claims.getSubject();
    }

    private String generateToken(UserDetails userDetails) {
        LocalDateTime expirationDate = LocalDateTime.now().plusMinutes(tokenExpirationMinutes);

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities())
                .issuedAt(new Date())
                .expiration(Timestamp.valueOf(expirationDate))
                .signWith(secretKey())
                .compact();
    }

    private Claims extractClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(secretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
