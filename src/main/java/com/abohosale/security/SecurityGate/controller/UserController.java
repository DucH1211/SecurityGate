package com.abohosale.security.SecurityGate.controller;

import com.abohosale.security.SecurityGate.entity.UserAccount;
import com.abohosale.security.SecurityGate.repository.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    @PostMapping(value = "register",consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public UserAccount register(
            @RequestParam("username") String username,@RequestParam("firstName")String firstName,
            @RequestParam("password")String password,@RequestParam("lastName")String lastName){
        UserAccount userAccount = new UserAccount();
        userAccount.setFirstName(firstName);
        userAccount.setLastName(lastName);
        userAccount.setUsername(username);
        userAccount.setPassword(passwordEncoder.encode(password));
        userAccount.setActive(true);
        return userAccountRepository.save(userAccount);
    }
    @GetMapping
    public List<UserAccount> getUsers(){
        return userAccountRepository.findAll();
    }
//    @GetMapping
//    public UserDetails getUser(Authentication authentication) {
//        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
//        Map<String, Object> attributes = token.getTokenAttributes();
//        return userDetailsService.loadUserByUsername(attributes.get("username").toString());
//    }
}