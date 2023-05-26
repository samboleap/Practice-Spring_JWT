package com.samboleap.spring_jwt_daoauthentication.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserAccount {
    private int id;
    private String username;
    private String email;
    private String passcode;
    private String gender;
    private  String address;
    private String role;
}
