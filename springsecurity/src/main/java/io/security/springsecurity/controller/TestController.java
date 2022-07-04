package io.security.springsecurity.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    /**
     *
     * 스프링 시큐리티 를 주입하면
     * 모든 요청은 인증이 되어야 자원에 접근이 가능하다.
     * 인증 방식은 form 로그인 방식과 httpBasic 로그인 방식을 제공한다.
     * 기본 계정 한 개를 제공한다.
     * id는 user
     * password는 기본적으로 서버 실행시 랜덤값으로 설정된다.
     */

    @GetMapping("/")
    public String index() {
        return "home";
    }

    @GetMapping("loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("expired")
    public String expired() {
        return "expired";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }
}
