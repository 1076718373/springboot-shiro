package com.hmb.springbootshiro.system.shiroconfig;

import com.hmb.springbootshiro.pojo.User;
import com.hmb.springbootshiro.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class SystemRealm extends AuthorizingRealm {
    @Autowired
    private UserService userService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("--------权限配置-------");
        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        User user = (User) principalCollection.getPrimaryPrincipal();
        //注入角色(查询所有的角色注入控制器）
        Set<String> roles = userService.selectRoleByUsername(user.getUsername());
        for (String role: roles){
            authorizationInfo.addRole(role);
        }
        //注入角色所有权限（查询用户所有的权限注入控制器）
        Set<String> permissions  =userService.selectPermissionByUsername(user.getUsername());
        for(String permission:permissions){
            authorizationInfo.addStringPermission(permission);
        }
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //1. 把 AuthenticationToken 转换为 UsernamePasswordToken
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        //2. 从 UsernamePasswordToken 中来获取 username
        String username = upToken.getUsername();
        System.out.println(upToken.getPassword());

        //3. 调用数据库的方法, 从数据库中查询 username 对应的用户记录
        User user = userService.selectUser(username);
        //第二个字段是credentials，注意这里是指从数据库中获取的password。
        Object credentials =user.getPassword();
        //1). principal: 认证的实体信息. 可以是 username, 也可以是数据表对应的用户的实体类对象.
        Object principal = user;
        //3. 调用数据库的方法, 从数据库中查询 username 对应的用户记录
        System.out.println("从数据库中获取 username: " + username + " 所对应的用户信息.");
        System.out.println("从数据库中获取 username: " + user.toString() + " 所对应的用户信息.");

        String realmName = getName();
        //4). 盐值.
        ByteSource credentialsSalt = ByteSource.Util.bytes(username);
        SimpleAuthenticationInfo info = null; //new SimpleAuthenticationInfo(principal, credentials, realmName);
        info = new SimpleAuthenticationInfo(principal,credentials,credentialsSalt,getName());
        System.out.println("+++++++++"+info);
        return info;
    }
}
