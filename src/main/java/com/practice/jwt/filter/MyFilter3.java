package com.practice.jwt.filter;

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
      String headerAut = req.getHeader("Authorization");
      System.out.println("필터3");

      if(headerAut.equals("cors")){
        chain.doFilter(req,res);
      } else {
        PrintWriter outPrintWriter = res.getWriter();
        outPrintWriter.println("인증안됨");
      }
    }
  }
}
