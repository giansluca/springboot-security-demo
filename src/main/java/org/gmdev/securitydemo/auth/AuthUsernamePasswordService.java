package org.gmdev.securitydemo.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class AuthUsernamePasswordService {

    private final AuthenticationManager authenticationManager;

    public AuthUsernamePasswordService(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public String attemptAuthentication(AuthRequest authRequest) {
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authRequest.getUsername(), authRequest.getPassword());

        authenticationManager.authenticate(authentication);
        return "Bearer Bebebebeb111";
    }


}
