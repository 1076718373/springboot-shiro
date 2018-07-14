package com.hmb.springbootshiro.pojo;

import lombok.Data;
import lombok.ToString;

import java.io.Serializable;

@Data
@ToString
public class User implements Serializable {
    private Integer id;
    private String username;
    private String password;
}
