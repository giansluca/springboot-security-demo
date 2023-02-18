package org.gmdev.securitydemo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Date;

@Configuration
public class JwtService {

    private static final String BEARER = "Bearer ";

    private final String secretKey;
    private final Integer tokenExpirationMinutes;
    private final String tokenPrefix;

    public JwtService(
            @Value("${application.jwt.secretKey:null}") String secretKey,
            @Value("${application.jwt.tokenExpirationMinutes:null}") Integer tokenExpirationMinutes) {

        this.secretKey = secretKey;
        this.tokenExpirationMinutes = tokenExpirationMinutes;
        this.tokenPrefix = BEARER;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }

    public SecretKey secretKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
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
        java.sql.Timestamp.valueOf(expirationDate);

        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Timestamp.valueOf(expirationDate))
                .signWith(secretKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims extractClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(secretKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

}
