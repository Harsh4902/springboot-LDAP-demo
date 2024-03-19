package com.example.ldap.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
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

    if (request.getRequestedSessionId() != null) {
      Authentication a = new CustomAuthentication(true,null);
      SecurityContextHolder.getContext().setAuthentication(a);
      filterChain.doFilter(request, response);
      return;
    }

    String uid = request.getHeader("uid");
    CustomAuthentication ca = new CustomAuthentication(false, uid);
    try{

      if(uid == null)
        throw new BadCredentialsException("Not authenticated");

      Authentication authentication = customAuthenticationManager.authenticate(ca);

      if (authentication.isAuthenticated()) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        HttpSession session = request.getSession(true);
        filterChain.doFilter(request, response);
      } else {
        // Handle unsuccessful authentication
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      }
    }
    catch (BadCredentialsException e){
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      System.err.println(e);
    }
  }
}
