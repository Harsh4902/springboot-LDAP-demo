package com.example.ldap.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CustomAuthentication implements Authentication {

  private final boolean authentication;

  public CustomAuthentication(boolean authentication, String uid) {
    this.authentication = authentication;
    this.uid = uid;
  }

  private final String uid;

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return null;
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public Object getDetails() {
    return null;
  }

  @Override
  public Object getPrincipal() {
    return null;
  }

  @Override
  public boolean isAuthenticated() {
    return authentication;
  }

  @Override
  public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

  }

  @Override
  public String getName() {
    return null;
  }

  public boolean isAuthentication() {
    return authentication;
  }

  public String getUid() {
    return uid;
  }
}
