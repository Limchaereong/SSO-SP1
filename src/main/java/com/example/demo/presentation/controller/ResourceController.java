package com.example.demo.presentation.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/resource")
public class ResourceController {

    @GetMapping("/protected")
    public String getProtectedResource() {
        return "sp1";
    }
    
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setMaxAge(0);
        accessTokenCookie.setPath("/");
        response.addCookie(accessTokenCookie);

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setMaxAge(0);
        refreshTokenCookie.setPath("/");
        response.addCookie(refreshTokenCookie);
        
        Cookie idTokenCookie = new Cookie("idToken", null);
        idTokenCookie.setMaxAge(0);
        idTokenCookie.setPath("/");
        response.addCookie(idTokenCookie);

        return "redirect:http://10.120.60.208:8080/loginForm";
    }
    
}