package org.gmdev.securitydemo.auth;

import java.util.Optional;

public interface UserDao {

    Optional<User> selectApplicationUserByUsername(String username);

}
