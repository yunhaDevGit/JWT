package com.practice.jwt.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

//@CrossOrigin  // 인증이 필요한 요청은 전부 거부된다. 인증이 필요하지 않은 요청만 허용
@RestController
public class RestApiController {

  @GetMapping("home")
  public String home() {
    return "<h1>home</h1>";
  }

  @PostMapping("token")
  public String token() {
    return "<h1>token</h1>";
  }
}
