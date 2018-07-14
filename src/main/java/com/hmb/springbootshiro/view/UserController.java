package com.hmb.springbootshiro.view;

import com.hmb.springbootshiro.pojo.Page;
import com.hmb.springbootshiro.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.crypto.CryptoException;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public Page login(String username,String password) throws UnsupportedEncodingException {
        Subject currentUser = SecurityUtils.getSubject();
        Map<Integer,String> map = new HashMap<>();
        if (!currentUser.isAuthenticated()) {
            // 把用户名和密码封装为 UsernamePasswordToken 对象
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            // rememberme
            token.setRememberMe(true);
            try {
                // 执行登录.
                currentUser.login(token);
            }catch (IncorrectCredentialsException e) {
                map.put(204, "密码错误");
            } catch (LockedAccountException e) {
                map.put(205, "登录失败，该用户已被冻结");
            } catch (AuthenticationException e) {
                map.put(206, "该用户不存在");
            }
        }
        return new Page(200,"登录成功",0,null);

    }
    @RequestMapping("/addUser")
    public boolean addUser(String username,String password){
        System.out.println("======addUser=======");
        System.out.println(username);
        //密码加密并set
        String password1 = SysMd5(username, password);
        boolean b = userService.add(username,password1);//将用户数据插入数据库
        return b;
    }

    //添加user的密码加密方法
    public  String  SysMd5(String username,String password) {
        String hashAlgorithmName = "MD5";//加密方式
        ByteSource salt = ByteSource.Util.bytes(username);//以账号作为盐值
        int hashIterations = 1024;//加密1024次
        SimpleHash hash = new SimpleHash(hashAlgorithmName,password,salt,hashIterations);
        return hash.toString();
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
