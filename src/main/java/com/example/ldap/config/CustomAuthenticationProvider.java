package com.example.ldap.config;

import com.example.ldap.entity.DBUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

  @Autowired
  private DBUserRepository dbUserRepository;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    CustomAuthentication ca = (CustomAuthentication) authentication;
    String uid = ca.getUid();

    if(dbUserRepository.findByUid(uid) == null){
      throw new BadCredentialsException("No such user is present in Database.....!");
    }
    return new CustomAuthentication(true,uid);
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return CustomAuthentication.class.equals(authentication);
  }
}
