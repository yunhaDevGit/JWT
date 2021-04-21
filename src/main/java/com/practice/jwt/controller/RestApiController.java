package com.practice.jwt.controller;

import com.practice.jwt.config.auth.PrincipalDetails;
import com.practice.jwt.model.User;
import com.practice.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

//@CrossOrigin  // 인증이 필요한 요청은 전부 거부된다. 인증이 필요하지 않은 요청만 허용
@RequiredArgsConstructor
@RestController
public class RestApiController {

  private final UserRepository userRepository;
  private final BCryptPasswordEncoder bCryptPasswordEncoder;

  @GetMapping("home")
  public String home() {
    return "<h1>home</h1>";
  }

  @PostMapping("token")
  public String token() {
    return "<h1>token</h1>";
  }

  @PostMapping("join")
  public String join(@RequestBody User user) {
    user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    user.setRoles("ROLE_USER");
    userRepository.save(user);
    return "회원가입 완료";
  }

  @GetMapping("/api/v1/user")
  public String user(Authentication authentication){
    PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
    System.out.println("authentication :" + principalDetails);
    return "user";
  }

  @GetMapping("/api/v1/manager")
  public String manager(){
    return "manager";
  }

  @GetMapping("/api/v1/admin")
  public String admin(){
    return "admin";
  }
}
