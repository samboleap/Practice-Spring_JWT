package com.samboleap.spring_jwt_daoauthentication.service;


import com.samboleap.spring_jwt_daoauthentication.model.UserAccount;
import com.samboleap.spring_jwt_daoauthentication.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;


@Service
public class UserService implements UserDetailsService {
   @Autowired
    private final UserRepo userRepo;

    public UserService(UserRepo userRepo) {
        this.userRepo = userRepo;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount users = userRepo.getAllUsers(username);
        return User.builder()
                .username(users.getUsername())
                .password(users.getPasscode())
                .roles("USER")
                .build();

    }
}
