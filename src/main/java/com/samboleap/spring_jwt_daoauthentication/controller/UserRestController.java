package com.samboleap.spring_jwt_daoauthentication.controller;

import com.samboleap.spring_jwt_daoauthentication.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/user")
public class UserRestController {
    @Autowired
    private final TokenService tokenService;

    public UserRestController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/home")
    public String homepage(){
        return "This is a home page!!!!";
    }

    @PostMapping("/token")
    public String getToken(Authentication authentication){
        return tokenService.generateToken(authentication);
    }
}
