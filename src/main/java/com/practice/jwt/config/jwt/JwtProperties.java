package com.practice.jwt.config.jwt;

public interface JwtProperties {
  String SECRETE = "cos";
  int EXPIRATION_TIME =60000*10;
  String TOKEN_PREFIX = "Bearer ";
  String HEADER_STRING = "Authorization";

}
