package org.gmdev.securitydemo.security;

import com.google.common.base.Strings;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.gmdev.securitydemo.auth.AuthUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

@Slf4j
@Configuration
public class JwtTokenVerifierFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AuthUserDetailService authUserDetailService;

    @Autowired
    public JwtTokenVerifierFilter(JwtService jwtService, AuthUserDetailService authUserDetailService) {
        this.jwtService = jwtService;
        this.authUserDetailService = authUserDetailService;
    }

    @Override
    protected void doFilterInternal(@Nullable HttpServletRequest request,
                                    @Nullable HttpServletResponse response,
                                    @Nullable FilterChain filterChain) throws ServletException, IOException {

        if (filterChain == null) throw new IllegalStateException("filterChain cannot be null!");
        if (request == null) throw new IllegalStateException("request cannot be null!");

        String authorizationHeader = request.getHeader(jwtService.getAuthorizationHeader());
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtService.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.replace(jwtService.getTokenPrefix(), "");

        try {
            String username = jwtService.extractUserName(token);
            UserDetails userDetails = authUserDetailService.loadUserByUsername(username);
            Collection<? extends GrantedAuthority> simpleGrantedAuthorities = userDetails.getAuthorities();

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e) {
            log.error(String.format("Token: %s cannot be trusted", token));
        }

        filterChain.doFilter(request, response);
    }

}
