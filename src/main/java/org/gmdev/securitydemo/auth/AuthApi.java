package org.gmdev.securitydemo.auth;

import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@Validated
@RestController
@RequestMapping(path = "/auth/v1")
public class AuthApi {

    private final AuthUsernamePasswordService authUsernamePasswordService;

    @Autowired
    public AuthApi(AuthUsernamePasswordService authUsernamePasswordService) {
        this.authUsernamePasswordService = authUsernamePasswordService;
    }

    @PostMapping(path = "/login")
    public ResponseEntity<Void> login(@RequestBody @Valid AuthRequest authRequest) {
        try {
            log.info(String.format("Attempt login with username: '%s' and password: '%s'",
                    authRequest.getUsername(), authRequest.getPassword()));

            String token = authUsernamePasswordService.attemptAuthentication(authRequest);

            log.warn("Login succeeded");
            return ResponseEntity.ok().header(HttpHeaders.AUTHORIZATION, token).build();
        } catch (UsernameNotFoundException | BadCredentialsException  e) {
            log.warn("Login failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }


}
