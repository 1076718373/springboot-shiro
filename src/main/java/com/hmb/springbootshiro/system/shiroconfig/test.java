package com.hmb.springbootshiro.system.shiroconfig;

import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;
import sun.applet.Main;

public class test {
    public static void main(String[] args) {
        String hashAlgorithmName = "MD5";
        Object credentials = "123456";
        ByteSource salt = ByteSource.Util.bytes("sandy");;


        SimpleAuthenticationInfo info = null; //new SimpleAuthenticationInfo(principal, credentials, realmName);
        info = new SimpleAuthenticationInfo("sandy", "123456", salt, "sandy");
        System.out.println(info.toString());
    }
}
