package com.hmb.springbootshiro.system.exception;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RoleException extends RuntimeException  {
    private Integer code;
    private String message;
}
