package org.gmdev.securitydemo.auth;

import lombok.extern.slf4j.Slf4j;
import org.gmdev.securitydemo.security.JwtService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
public class AuthUsernamePasswordService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthUsernamePasswordService(AuthenticationManager authenticationManager,
                                       JwtService jwtService) {

        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public String attemptAuthentication(AuthRequest authRequest) {
        Authentication authenticate = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));

        LocalDateTime expirationDate = LocalDateTime.now().plusMinutes(jwtService.getTokenExpirationMinutes());
        java.sql.Timestamp.valueOf(expirationDate);

        UserDetails userDetails = (UserDetails) authenticate.getPrincipal();
        return jwtService.generateBearerToken(userDetails);
    }


}
