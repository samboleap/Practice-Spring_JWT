package com.samboleap.spring_jwt_daoauthentication.repo;

import com.samboleap.spring_jwt_daoauthentication.model.UserAccount;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface UserRepo {
    @Select("select * from accountstb where username like #{username}")
    UserAccount getAllUsers(String username);
}
