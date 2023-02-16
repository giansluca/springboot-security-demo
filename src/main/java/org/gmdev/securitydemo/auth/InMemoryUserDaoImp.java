package org.gmdev.securitydemo.auth;

import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static org.gmdev.securitydemo.auth.UserRole.*;

@Repository("inMemoryUserDao")
public class InMemoryUserDaoImp implements UserDao {

    private final PasswordEncoder passwordEncoder;

    public InMemoryUserDaoImp(
             @Autowired @Qualifier(value = "bcryptPasswordEncoder") PasswordEncoder passwordEncoder) {

        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<User> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> applicationUser.getUsername().equals(username))
                .findFirst();
    }

    public List<User> getApplicationUsers() {
        return Lists.newArrayList(
                new User(
                        "gians",
                        passwordEncoder.encode("12345"),
                        STUDENT.getGrantedAuthorities(),
                        true, true, true, true
                ),
                new User(
                        "tom",
                        passwordEncoder.encode("12345"),
                        MANAGER.getGrantedAuthorities(),
                        true, true, true, true
                ),
                new User(
                        "terence",
                        passwordEncoder.encode("12345"),
                        ADMIN.getGrantedAuthorities(),
                        true, true, true, true
                )
        );
    }

}
