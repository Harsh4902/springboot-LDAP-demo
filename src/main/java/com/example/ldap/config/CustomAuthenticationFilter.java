package com.example.ldap.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class CustomAuthenticationFilter extends OncePerRequestFilter {

  @Autowired
  private CustomAuthenticationManager customAuthenticationManager;

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    String uid = request.getHeader("uid");
    CustomAuthentication ca = new CustomAuthentication(false,uid);

    var a = customAuthenticationManager.authenticate(ca);

    if(a.isAuthenticated()){
      SecurityContextHolder.getContext().setAuthentication(a);
      filterChain.doFilter(request,response);
    }

  }
}
