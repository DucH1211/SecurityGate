package com.abohosale.security.SecurityGate.auth.component;

import com.abohosale.security.SecurityGate.auth.common.user.CustomUserDetails;
import com.abohosale.security.SecurityGate.entity.UserAccount;
import com.abohosale.security.SecurityGate.repository.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
@RequiredArgsConstructor
public class DatabaseUserDetailService implements UserDetailsService {
    private final UserAccountRepository userAccountRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount userAccount = userAccountRepository.findByUsername(username);
        if(userAccount == null){
            throw new UsernameNotFoundException(String.format("User with username [%s] not found",username));
        }
        return new CustomUserDetails(userAccount);
    }
}
