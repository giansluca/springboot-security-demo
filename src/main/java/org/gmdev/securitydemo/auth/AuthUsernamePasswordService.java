package org.gmdev.securitydemo.auth;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.util.Date;

@Slf4j
@Service
public class AuthUsernamePasswordService {

    private final AuthenticationManager authenticationManager;
    private final SecretKey secretKey;

    public AuthUsernamePasswordService(AuthenticationManager authenticationManager,
                                       SecretKey secretKey) {

        this.authenticationManager = authenticationManager;
        this.secretKey = secretKey;
    }

    public String attemptAuthentication(AuthRequest authRequest) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

        LocalDateTime expirationDate = LocalDateTime.now().plusMinutes(10);
        java.sql.Timestamp.valueOf(expirationDate);

        String token = Jwts.builder()
                .setSubject(authenticate.getName())
                .claim("authorities", authenticate.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Timestamp.valueOf(expirationDate))
                .signWith(secretKey)
                .compact();

        return String.format("Bearer %s", token);
    }


}
