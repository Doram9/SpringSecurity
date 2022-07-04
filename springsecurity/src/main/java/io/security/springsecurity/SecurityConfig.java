package io.security.springsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


@Configuration
@EnableWebSecurity //웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //유저 생성
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "ADMIN");
    }

    //authentication : 인증(유저가 누구인지 확인하는 절차,(로그인, 회원가입))
    //authorization : 인가(유저에 대한 권한을 허락하는 것)
    @Override
    protected void configure(HttpSecurity http) throws Exception { //httpSecurity 설정
        http
                //if문처럼 먼저 걸리는 matcher로 빠져나가기 때문에 무조건 구체적인 endPoint를 상위에 작성해야한다
                .authorizeRequests()
                .antMatchers("/login").permitAll() //로그인페이지는 인증 없이 누구나 접근 가능
                .antMatchers("/user").hasRole("USER")
                .antMatchers("/admin/pay").hasRole("ADMIN")
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();
                //.anyRequest().authenticated(); : 어떤 endpoint 요청이든 다 인증 처리

        http
                .formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache(); //사용자의 요청 정보를 담고 있는 캐시(session에 들어있음)
                        SavedRequest savedRequest = requestCache.getRequest(request, response); //
                        System.out.println(savedRequest);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl);
                    }
                })
                ;

        http
                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied");
                    }
                })
                ;
//        http
//                .formLogin()
//                .defaultSuccessUrl("/")
//                //.loginPage("/loginPage")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication :" + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception : " + exception.getMessage());
//                        response.sendRedirect("/");
//                    }
//                })
//                .permitAll() //인증 없이 누구나 접근 가능
//        ;
//
//        http
//                //로그아웃 처리
//                .logout()
//                .logoutUrl("/logout") //기본적으로 logout 처리는 post 방식으로 한다
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/");
//                    }
//                })
//                ;
//        http
//                //rememberMe 쿠키 생성
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService)
//                ;
//
//        http
//                .sessionManagement()
//                .maximumSessions(1) //최대 세션 허용 개수
//                //.maxSessionsPreventsLogin(false) //false : 동시 로그인 허용 - 로그인시 이전 session 만료
//                .maxSessionsPreventsLogin(true) //true : 동시 로그인 차단 - 로그인시 인증 실패
//                //.expiredUrl(url) //세션 만료시 이동 url
//        ;
//        http
//                .sessionManagement()
//                .sessionFixation().none(); //JSessionID 변경x -> 공격에 취약
//                //.sessionFixation().changeSessionId(); //로그인 시 JSessionID 변경
//
//        http
//                .sessionManagement()
//                .sessionCreationPolicy( //세션 정책
//                    SessionCreationPolicy.ALWAYS //세션 항상 생성
////                    SessionCreationPolicy.IF_REQUIRED //스프링시큐리티가 필요 시 생성(기본값)
////                    SessionCreationPolicy.NEVER //스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
////                    SessionCreationPolicy.STATELESS // 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
//                )
//                ;
    }
}
