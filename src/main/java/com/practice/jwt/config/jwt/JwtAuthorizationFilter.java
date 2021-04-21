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

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

  private UserRepository userRepository;

  public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
    super(authenticationManager);
    this.userRepository = userRepository;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

    System.out.println("인증이나 권한이 필요한 주소가 요청이 됨");

    String jwtHeader = request.getHeader(HEADER_STRING);
    System.out.println("jwtHeader : " + jwtHeader);

    if(jwtHeader == null || !jwtHeader.startsWith(TOKEN_PREFIX)){
      chain.doFilter(request, response);
      return;
    }

    String jwtToken = request.getHeader(HEADER_STRING).replace(TOKEN_PREFIX, "");

    String username =
        JWT.require(Algorithm.HMAC512(SECRETE)).build().verify(jwtToken).getClaim("username").asString();

    if(username!=null) {
      System.out.println("username 정상");
      User userEntity = userRepository.findByUsername(username);
      System.out.println("UserEntity : " + userEntity.getUsername());

      PrincipalDetails principalDetails = new PrincipalDetails(userEntity);


      Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

      SecurityContextHolder.getContext().setAuthentication(authentication);

      chain.doFilter(request, response);

    }

  }
}
