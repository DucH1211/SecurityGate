package com.abohosale.security.SecurityGate.controller;

import com.abohosale.security.SecurityGate.auth.JwtHelper;
import com.abohosale.security.SecurityGate.auth.WebSecurityConfig;
import com.abohosale.security.SecurityGate.common.login.LoginResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * controller to handle login request
 */
@RestController
public class AuthController {
    private final JwtHelper jwtHelper;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public AuthController(JwtHelper jwtHelper, UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.jwtHelper = jwtHelper;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * the login url to create a JWT token with id and authorities included in the claims
     * @param username
     * @param password
     * @return
     */
    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping(path = "login", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public LoginResult login(
            @RequestParam String username,
            @RequestParam String password){
        UserDetails userDetails;
        try{
            userDetails = userDetailsService.loadUserByUsername(username);
        }catch(UsernameNotFoundException e){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found");
        }

        if(passwordEncoder.matches(password,userDetails.getPassword())){
            Map<String,String> claims = new HashMap<>();
            claims.put("username",username);
            //adding authorities as space separated values to the jwt claims
            String authorities = userDetails.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.joining(","))
                    .replace(","," ");
            //.replace() used fixing error in collectors.joining("") did not join as expected.
            claims.put(WebSecurityConfig.AUTHORITIES_CLAIM_NAME,authorities);
            claims.put("userId",String.valueOf(1));
            String jwt = jwtHelper.createJwtForClaims(username,claims);
            return new LoginResult(jwt);
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"User not authenticated");
    }


}
