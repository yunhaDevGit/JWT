package com.practice.jwt.config.jwt;

import static com.practice.jwt.config.jwt.JwtProperties.HEADER_STRING;
import static com.practice.jwt.config.jwt.JwtProperties.SECRETE;
import static com.practice.jwt.config.jwt.JwtProperties.TOKEN_PREFIX;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.practice.jwt.config.auth.PrincipalDetails;
import com.practice.jwt.model.User;
import com.practice.jwt.repository.UserRepository;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// 인증 요청이 있을 때 동작하는게 아니라 시큐리티가 filter를 가지고 있는데
// 그 필터 중 BasicAuthenticationFilter가 있다.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어 있다.
// 만약 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탄다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

  private UserRepository userRepository;

  public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  // 인증이나 권한이 필요한 주소 요청이 있을 때 해당 필터를 타게 된다.
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

    System.out.println("인증이나 권한이 필요한 주소가 요청이 됨");

    String jwtHeader = request.getHeader(HEADER_STRING);
    System.out.println("jwtHeader : " + jwtHeader);

    // header가 없거나, Bearer가 아니면 다시 필터를 타게 넘긴다
    if(jwtHeader == null || !jwtHeader.startsWith(TOKEN_PREFIX)){
      chain.doFilter(request, response);
      return;
    }

    // JWT 토큰을 검증해서 정상적인 사용자인지 확인
    String jwtToken = request.getHeader(HEADER_STRING).replace(TOKEN_PREFIX, "");

    String username =
        JWT.require(Algorithm.HMAC512(SECRETE)).build().verify(jwtToken).getClaim("username").asString();

    // 서명이 정상적으로 됨
    if(username!=null) {
      System.out.println("username 정상");
      User userEntity = userRepository.findByUsername(username);
      System.out.println("UserEntity : " + userEntity.getUsername());

      PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

      // JWT 토큰 서명을 통해서 정상이면 Authentication 객체를 만들어준다
      Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

      // 시큐리티를 저장할 수 있는 세션 공간을 찾아서 authentication을 넣어준다
      // 강제로 시큐리티의 세션에 접근하여 Authentication 객체 저장
      SecurityContextHolder.getContext().setAuthentication(authentication);

      chain.doFilter(request, response);

    }

  }
}
