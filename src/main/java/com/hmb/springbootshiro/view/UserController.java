package com.hmb.springbootshiro.view;

import com.hmb.springbootshiro.pojo.Page;
import com.hmb.springbootshiro.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.ExpiredCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.util.Set;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;
    @PostMapping("/login")
    public Page login(String username,String password) throws UnsupportedEncodingException {
        Subject currentUser = SecurityUtils.getSubject();
        if (!currentUser.isAuthenticated()) {
            // 把用户名和密码封装为 UsernamePasswordToken 对象
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            // rememberme
            token.setRememberMe(true);
            try {
                System.out.println("1. " + token.getPassword());
                // 执行登录.
                currentUser.login(token);
            }
            // 所有认证时异常的父类.
            catch (AuthenticationException ae) {
                //unexpected condition?  error?
                System.out.println("登录失败: " + ae.getMessage());
                return new Page(201,"登录失败",0,ae.getMessage());
            }
        }
        return new Page(200,"登录成功",0,null);
    }
    @GetMapping("/article")
    public Page article() {
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            return new Page(200, "You are already logged in",0, null);
        } else {
            throw new ExpiredCredentialsException("You are guest");
        }
    }

    /**
     * 用户必须登录
     */
    @GetMapping("/require_auth")
    @RequiresAuthentication
    public Page requireAuth() {
        try {
            return new Page(200, "You are authenticated", 0,null);
        }catch (CryptoException e){
            throw new ExpiredCredentialsException("您没有登录");
        }

    }

    @GetMapping("/require_role")
    @RequiresRoles("管理员")
    public Page requireRole() {
        try {
            return new Page(200, "You are visiting require_role",0, null);
        }catch (CryptoException e){
            throw  new ExpiredCredentialsException( "您没有权限");
        }

    }

    @GetMapping("/require_permission")
    @RequiresPermissions(logical = Logical.OR, value = {"添加用户", "删除用户"})
    public Page requirePermission() {
        try {
            return new Page(200, "You are visiting permission require edit,view",0, null);
        }catch (CryptoException e){
            throw new ExpiredCredentialsException("您没有权限");
        }
    }
}
