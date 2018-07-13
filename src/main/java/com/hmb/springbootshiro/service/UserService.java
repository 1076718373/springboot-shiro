package com.hmb.springbootshiro.service;

import com.hmb.springbootshiro.dao.UserDao;
import com.hmb.springbootshiro.pojo.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class UserService {
    @Autowired
    private UserDao userDao;

    public User selectUser(String username) {
        return userDao.selectUser(username);

    }

    public Set<String> selectRoleByUsername(String username) {
        return userDao.selectRoleByUsername(username);
    }

    public Set<String> selectPermissionByUsername(String username) {
        return userDao.selectPermissionByUsername(username);
    }

    public boolean add(String username, String password1) {
        return userDao.add(username,password1);
    }
}
