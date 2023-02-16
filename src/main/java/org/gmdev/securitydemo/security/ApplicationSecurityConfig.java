//package org.gmdev.securitydemo.security;
//
//import org.gmdev.securitydemo.auth.AuthUserService;
//import org.gmdev.securitydemo.jwt.JwtConfig;
//import org.gmdev.securitydemo.jwt.JwtTokenVerifier;
//import org.gmdev.securitydemo.jwt.JwtUsernameAndPasswordAuthFilter;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Qualifier;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.authentication.HttpStatusEntryPoint;
//
//import javax.crypto.SecretKey;
//
//@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
//
//    private final PasswordEncoder passwordEncoder;
//    private final AuthUserService applicationUserService;
//    private final JwtConfig jwtConfig;
//    private final SecretKey secretKey;
//
//    @Autowired
//    public ApplicationSecurityConfig(
//            @Qualifier(value = "bcryptPasswordEncoder") PasswordEncoder passwordEncoder,
//            AuthUserService applicationUserService,
//            JwtConfig jwtConfig,
//            SecretKey secretKey) {
//
//        this.passwordEncoder = passwordEncoder;
//        this.applicationUserService = applicationUserService;
//        this.jwtConfig = jwtConfig;
//        this.secretKey = secretKey;
//
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        // Jwt Auth
//        // CSRF should be enabled fo browser client submission (not service)
//        // Authorization matcher are in place using annotation '@PreAuthorize' on controller
//        http
//                .exceptionHandling().authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
//                .and()
//                .csrf().disable()
//                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//                .and()
//                .addFilter(new JwtUsernameAndPasswordAuthFilter(authenticationManager(), jwtConfig, secretKey))
//                .addFilterAfter(new JwtTokenVerifier(jwtConfig, secretKey), JwtUsernameAndPasswordAuthFilter.class)
//                .authorizeRequests()
//                //.antMatchers("/swagger-ui/**").permitAll()
//                .anyRequest().authenticated();
//    }
//
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) {
//        auth.authenticationProvider(daoAuthenticationProvider());
//    }
//
//    public DaoAuthenticationProvider daoAuthenticationProvider() {
//        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setPasswordEncoder(passwordEncoder);
//        provider.setUserDetailsService(applicationUserService);
//        provider.setHideUserNotFoundExceptions(false);
//        return provider;
//    }
//
//
//}
