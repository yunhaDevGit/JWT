package com.practice.jwt.filter;

import static com.practice.jwt.config.jwt.JwtProperties.HEADER_STRING;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter {

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest req = (HttpServletRequest)request;
    HttpServletResponse res = (HttpServletResponse)response;


    if(req.getMethod().equals("POST")) {
      System.out.println("POST 요청됨");
      String headerAut = req.getHeader(HEADER_STRING);
      System.out.println("필터3");

      // cors 라는 값으로 토큰이 넘어오면 filter를 타게끔
      // id, password가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다
      // 요청할 때마다 header에 Authorization에 value 값으로 토큰을 가지고 온다
      // 그 때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지 검증만 하면 된다.
      if(headerAut.equals("cos")){
        chain.doFilter(req,res);
      } else {
        PrintWriter outPrintWriter = res.getWriter();
        outPrintWriter.println("인증안됨");
      }
    }
  }
}
