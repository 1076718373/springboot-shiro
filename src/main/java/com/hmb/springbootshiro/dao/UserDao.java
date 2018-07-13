package com.hmb.springbootshiro.dao;

import com.hmb.springbootshiro.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.Set;

@Mapper
@Repository
public interface UserDao {

    public User selectUser(@Param("username") String username);

    Set<String> selectRoleByUsername(String username);

    Set<String> selectPermissionByUsername(String username);

    boolean add(@Param("username") String username,@Param("password") String password);
}
