package com.practice.jwt.config;

import com.practice.jwt.filter.MyFilter1;
import com.practice.jwt.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

  // SecurityFilterChain에 Filter를 등록하는 것이 아니라 그냥 등록하는 것
  // request 요청이 올 때 동작한다
  // SecurityFilter가 다 실행 후에 실행된다.(SecurityFilterChain이 먼저 실행된다)
  // 만약 가장 먼저 실행되길 원한다면 Security
  @Bean
  public FilterRegistrationBean<MyFilter1> filter1() {
    FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
    bean.addUrlPatterns("/*");
    bean.setOrder(0); // 낮은 번호가 필터 중 가장 먼저 실행된다
    return bean;
  }

  @Bean
  public FilterRegistrationBean<MyFilter2> filter2() {
    FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
    bean.addUrlPatterns("/*");
    bean.setOrder(1);
    return bean;
  }
}
