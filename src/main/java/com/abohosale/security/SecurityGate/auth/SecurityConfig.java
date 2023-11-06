package com.abohosale.security.SecurityGate.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * currently has the password encoder bean config
 */
@Configuration
public class SecurityConfig {
    @Bean //bean used to encode user password with bcrypt
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

}
