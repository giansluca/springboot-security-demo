package org.gmdev.securitydemo.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor @Getter
@NoArgsConstructor
public class UsernameAndPasswordAuthRequest {

    private String username;
    private String password;

}
