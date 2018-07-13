package com.hmb.springbootshiro.pojo;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Page {
    private Integer code;
    private String msg;
    private long count;
    private Object data;
}