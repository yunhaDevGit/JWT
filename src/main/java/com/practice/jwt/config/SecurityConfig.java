package com.practice.jwt.config;


import com.practice.jwt.config.jwt.JwtAuthenticationFilter;
import com.practice.jwt.config.jwt.JwtAuthorizationFilter;
import com.practice.jwt.filter.MyFilter3;
import com.practice.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity // 기본적인 WebSecurity를 활성화 한다.
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final CorsFilter corsFilter;
  private final UserRepository userRepository;

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    // BasicAuthenticationFilter가 실행되기 전에 MyFilter3를 실행한다
    // http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);
    // 만약 직접 정의한 filter가 securityFilterChain을 먼저 실행시키고 싶을 경우
    // http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
    // SecurityContextPersistenceFilter가 securityFilterChain에서 가장 먼저 실행된다.

    http.csrf().disable();

    // 세션을 사용하지 않겠다 -> stateless 서버로 만들겠다
    // (기본적으로 웹은 stateless인데 그걸 statefull처럼 사용하기 위해 session과 cookie를 사용한다 하지만 그 방식을 사용하지 않겠다는 뜻)
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .addFilter(corsFilter) // crosorigin 정책 사용 x
            // 인증 있을 때 security filter에 등록!! (cross origin 정책 사용 x - 모든 요청 허용)
        .formLogin().disable() // formLogin 안쓰겠다 (jwt 방식으로 로그인 하기 때문에 기존에 id, pw 쓸 필요 x)
        .httpBasic().disable() // 기존의 하던 방식과는 다른 방식
        .addFilter(new JwtAuthenticationFilter(authenticationManager()))
        .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
        .authorizeRequests()
        .antMatchers("/api/v1/user/**")
        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/manager/**")
        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/v1/admin/**")
        .access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll(); // 다른 요청은 전부 허용(권한 없이 접근 가능)
  }

}
