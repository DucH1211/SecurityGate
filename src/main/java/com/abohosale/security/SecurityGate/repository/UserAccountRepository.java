package com.abohosale.security.SecurityGate.repository;

import com.abohosale.security.SecurityGate.entity.UserAccount;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserAccountRepository extends JpaRepository<UserAccount,Integer> {
    UserAccount findByUsername(String username); //this is automatically implemented by JpaRepo
}
