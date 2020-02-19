package com.mb.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
@ToString
public class AuthUser implements Serializable {
    @JsonProperty("userName")
    private String userName;

    @JsonProperty("password")
    private String password;
}
