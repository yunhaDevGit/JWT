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


// /login 요청을 해서 username, password 전송하면(post) UsernamePasswordAuthenticationFilter가 동작을 한다.
// 하지만 SecurityConfig에서 formLogin().disable() 설정을 했기 때문에 동작을 안한다.
// 이 필터가 동작하게끔 하고 싶으면 SecurityConfig에 .addFilter(new JwtAuthenticationFilter())를 해주면 된다
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

  // UsernamePasswordAuthenticationFilter는 로그인을 진행하는 필터이기 때문에 AuthenticationManager를 통해 로그인 진행
  private final AuthenticationManager authenticationManager;


  // /login 요청을 하면 로그인 시도를 위해 실행되는 함수
  // 1. username, password 받는다
  // 2. 정상인지 로그인 시도를 해본다. 받아온 authenticationManager로 로그인 시도를 하면
  //    PrincipalDetailsService가 호출된다. 그러면 loadUserByUsername() 함수 실행된다.
  // 3. loadUserByUsername()에서 정상적으로 PrincipalDetails가 return 되면 PrincipalDetails를 세션에 담는다 (권한 관리를 위해서)
  //    세션에 안담으면 권한 관리가 안된다. (권한 관리를 안할거면 세션에 담지 않아도 된다)
  // 4. JWT 토큰을 만들어서 응답해주면 된다
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
      // username, password 담겨 있다
      User user = objectMapper.readValue(request.getInputStream(), User.class);
      System.out.println("user : " + user);

      // Token 만들기
      UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

      // 만든 token으로 로그인 시도
      // PrincipalDetailsService의 loadUserByUsername()이 실행된다.
      // loadUserByUsername()은 username만 가지고 간다. password는 spring이 알아서 처리해준다
      // authenticationManager에 token을 넘겨서 던저주면 인증을 해준다.
      // authentication에 내 로그인 정보가 담긴다.
      // -> PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 authentication이 리턴된다
      // DB에 있는 username과 password가 일치한다
      Authentication authentication = authenticationManager.authenticate(authenticationToken);

      PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();

      System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());

      System.out.println("request.getInputStream().toString()" + request.getInputStream().toString());

      // authentication 객체가 session 영역에 저장된다. => return을 통해!
      // return 해주는 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거다.
      // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없지만 단지 권한 처리 때문에 session에 넣어주는 것.
      return authentication;

    } catch (IOException e) {
      e.printStackTrace();
    }
    return null;
  }

  // attemptAuthentication() 실행 후 인증이 정상적으로 되었으면 successfulAuthentication()가 실행된다
  // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response(응답) 해주면 된다.
  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authResult) throws IOException, ServletException {

    System.out.println("successfulAuthentication 실행됨 -> 인증이 완료됨");
    PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

    // JWT 라이브러리를 사용하여 토큰 생성
    // RSA 방식이 아닌 Hash 암호 방식
    String jwtToken = JWT.create()
        .withSubject("yunha token")
        .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // 토큰 유효시간
        .withClaim("id", principalDetails.getUser().getId()) // withClaim - 내가 넣고 싶은 key-value 값
        .withClaim("username", principalDetails.getUser().getUsername())
        .sign(Algorithm.HMAC512(SECRETE));

    // 사용자에게 응답할 response의 header에 토큰 넣어준다다
   response.addHeader(HEADER_STRING,TOKEN_PREFIX + jwtToken);
  }
}


// username, password -> 로그인 정상
// 서버쪽 세션 ID 생성
// 클라이언트 쿠키 세션 ID를 응답
// 요청할 때마다 쿠키값 세션 ID를 항상 들고 서버쪽로 요청하기 때문에
// 서버는 세션 ID가 유효한지 판단해서 유효하면 인증이 필요한 페이지로 접근하게 하면 된다
// session.getAttribute("세션 값") 을 통해 유효성 검사

// ---------------------------------------------

// username, password -> 로그인 정상
// JWT 토큰 생성
// 클라이언트 쪽으로 JWT 토큰 응답
// 요청할 때마다 JWT 토큰 가지고 요청
// 서버는 JWT 토큰이 유효한지를 판단(필터를 통해)