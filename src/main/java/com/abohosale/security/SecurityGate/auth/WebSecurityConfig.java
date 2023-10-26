package com.abohosale.security.SecurityGate.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class WebSecurityConfig {
    private final PasswordEncoder passwordEncoder;

    public WebSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * add Oauth2 resource Server adds the following class,
     * BearerTokenAuthenticationFilter, authenticate the incoming requests with JWT in header,
     * JWT Authentication Provider, the BearerTokenAuthenticationFilter will give the token to this class via AuthenticationManager
     * and JWTDecoder in JWTAuthenticationProvider will decode and validate received JWTs
     * This SecurityConfig uses a custom decoder instead of the auto configured JwtDecoder.
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(Customizer.withDefaults()) //add default cors filter
                .csrf(csrf -> csrf.disable()) //disable csrf protection
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                ) //not using sessions(state) in this case
                .authorizeHttpRequests(config ->
                        config
                                .requestMatchers("/error", "/login")
                                .permitAll() //permits all request to .error and login
                                .anyRequest()
                                .authenticated() //authenticate the rany other request
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2
                                .jwt(Customizer.withDefaults())
                );  //oauth2 resource server running on the side,
                    // authenticate the above config with jwt,
                    // all requests coming should have
                    //an authorization header which contain a valid JWT.
                    // Authorization: Bearer <jwt_token>
        return http.build();
    }
    //we need to read the public key from the keystore insread of the  'jwt-set-url' (or jwt issuer uri)

    @Bean
    public InMemoryUserDetailsManager userDetailsManager(){
        UserDetails user = User
                .withUsername("user")
                .authorities("USER")
                .passwordEncoder(passwordEncoder::encode)
                .password("1234")
                .build();
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(user);
        return manager;
    }
}
