package com.abohosale.security.SecurityGate.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity //byDefault have prePostEnabled
public class WebSecurityConfig {
    public static final String AUTHORITIES_CLAIM_NAME = "roles";

    private final PasswordEncoder passwordEncoder;

    public WebSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * add Oauth2 resource Server adds the following class,
     * BearerTokenAuthenticationFilter, authenticate the incoming requests with JWT in header,
     * JWT Authentication Provider, the BearerTokenAuthenticationFilter will give the token to this class via AuthenticationManager
     * and JWTDecoder in JWTAuthenticationProvider will decode and validate received JWTs
     * This SecurityConfig uses a custom decoder instead of the autoconfigured JwtDecoder.
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
                                .jwt(
                                        jwt -> jwt
                                                .jwtAuthenticationConverter(authenticationConverter()))
                        //change default behavior of oauth2 jwt() using custom jwtAuthenticationConverter

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
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        UserDetails user1 = User
                .withUsername("user1")
                .authorities("ADMIN,STAFF_MEMBER") //oauth2 will read this from roles prop in claims
                .passwordEncoder(passwordEncoder::encode)
                .password("1234")
                .build();
        manager.createUser(user1);
        UserDetails user2 = User
                .withUsername("user2")
                .authorities("STAFF_MEMBER")
                .passwordEncoder(passwordEncoder::encode)
                .password("1234")
                .build();
        manager.createUser(user2);
        UserDetails user3 = User
                .withUsername("user3")
                .authorities("ASSISTANT_MANAGER","STAFF_MEMBER")
                .passwordEncoder(passwordEncoder::encode)
                .password("1234")
                .build();
        manager.createUser(user3);
        UserDetails user4 = User
                .withUsername("user4")
                .authorities("USER")
                .passwordEncoder(passwordEncoder::encode)
                .password("1234")
                .build();
        manager.createUser(user4);

        return manager;
    }

    /**
     * A method to return a JwtAuthenticationConverter with different ClaimName, and Prefix.
     * Oath2 Uses JwtAuthenticationConverter to convert received Bearer token to a JwtAuthenticationToken type
     * this class uses JwtGrantedAuthoritiesConverter to read the granted authorities
     * By Default, this class expects a JWT claim named scope, or scp and will add prefix SCOPE_ to every granted authorities
     * We don't want this behavior, will be redundant when integrating with multiple layer.
     * This Method implements a custom behavior to set prefix to  "" and claim name to "roles"
     * @return JwtAuthenticationConverter
     */
    protected JwtAuthenticationConverter authenticationConverter(){
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("");
        authoritiesConverter.setAuthoritiesClaimName(AUTHORITIES_CLAIM_NAME);

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
