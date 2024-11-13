package org.gmdev.securitydemo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final DaoAuthenticationProvider daoAuthenticationProvider;
    private final JwtTokenVerifierFilter jwtTokenVerifierFilter;

    @Autowired
    public SecurityConfig(
            DaoAuthenticationProvider daoAuthenticationProvider,
            JwtTokenVerifierFilter jwtTokenVerifierFilter) {

        this.daoAuthenticationProvider = daoAuthenticationProvider;
        this.jwtTokenVerifierFilter = jwtTokenVerifierFilter;
    }

    private static final String[] AUTH_WHITELIST = {
            "/auth/**",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/info",
            "/health"
    };

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(requests ->
                        requests
                        .requestMatchers(AUTH_WHITELIST).permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .exceptionHandling(handler ->
                        handler.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
                )
                .authenticationProvider(daoAuthenticationProvider)
                .addFilterBefore(jwtTokenVerifierFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


}
