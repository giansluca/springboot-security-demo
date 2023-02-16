package org.gmdev.securitydemo.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor @Getter
public class AuthRequest {

    @NotBlank
    @Size(max = 32)
    private final String username;

    @NotBlank
    @Size(max = 32)
    private final String password;

}
