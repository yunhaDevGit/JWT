package com.practice.jwt.config.auth;

import com.practice.jwt.model.User;
import com.practice.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login 요청 올 때 동작한다. -> 하지만 여기서는 동작 안한다.
// 그냥 하게 되면 404 에러 발생
// spring security config에서 .formLogin().disable() 설정을 했기 때문
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    System.out.println("PrincipalDetailsService의 loadUserByUsername 실행");
    User userEntity = userRepository.findByUsername(username);
    System.out.println("userEntity : " + userEntity);
    return new PrincipalDetails(userEntity);
  }
}
