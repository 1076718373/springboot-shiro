package com.hmb.springbootshiro.system.exception;

import com.hmb.springbootshiro.pojo.Page;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authc.ExpiredCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.crypto.CryptoException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionController {
    /**
     *  捕捉shiro的异常
     */
    @ExceptionHandler(ShiroException.class)
    public Page handle401(ShiroException e) {

        return new Page(401, "你没有权限访问该资源!!!", 0,null);
    }

//    @ExceptionHandler(UnknownAccountException.class)
//    public Page handle402(UnknownAccountException e) {
//
//        return new Page(402, "用户名或密码错误", 0,null);
//    }
}
