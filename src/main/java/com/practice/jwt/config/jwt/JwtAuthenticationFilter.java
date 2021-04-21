package com.practice.jwt.config.jwt;

import static com.practice.jwt.config.jwt.JwtProperties.EXPIRATION_TIME;
import static com.practice.jwt.config.jwt.JwtProperties.HEADER_STRING;
import static com.practice.jwt.config.jwt.JwtProperties.SECRETE;
import static com.practice.jwt.config.jwt.JwtProperties.TOKEN_PREFIX;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.jwt.config.auth.PrincipalDetails;
import com.practice.jwt.model.User;
import java.io.IOException;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  private final AuthenticationManager authenticationManager;

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request,
      HttpServletResponse response) throws AuthenticationException {
    System.out.println("JwtAuthenticationFilter : 로그인 시도 중");

    try {
//      BufferedReader bufferedReader = request.getReader();
//
//      String input =  null;
//      while((input=bufferedReader.readLine()) != null){
//        System.out.println(input);
//      }

      ObjectMapper objectMapper = new ObjectMapper();
      User user = objectMapper.readValue(request.getInputStream(), User.class);
      System.out.println("user : " + user);

      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

      Authentication authentication = authenticationManager.authenticate(authenticationToken);

      PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
      System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());

      System.out.println("request.getInputStream().toString()" + request.getInputStream().toString());

      return authentication;

    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {
    System.out.println("successfulAuthentication 실행됨 -> 인증이 완료됨");
    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

    String jwtToken = JWT.create()
        .withSubject("yunha token")
        .withExpiresAt(new Date(System.currentTimeMillis()+ EXPIRATION_TIME))
        .withClaim("id", principalDetails.getUser().getId())
        .withClaim("username", principalDetails.getUser().getUsername())
        .sign(Algorithm.HMAC512(SECRETE));

    response.addHeader(HEADER_STRING,TOKEN_PREFIX + jwtToken);
  }
}
