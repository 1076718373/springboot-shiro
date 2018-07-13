package com.hmb.springbootshiro.pojo;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class User {
    private Integer id;
    private String username;
    private String password;
}
