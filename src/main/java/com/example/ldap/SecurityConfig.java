package com.example.ldap;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.ldap.EmbeddedLdapServerContextSourceFactoryBean;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.config.ldap.LdapPasswordComparisonAuthenticationManagerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.server.UnboundIdContainer;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

//  @Bean
//  public EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean() {
//    EmbeddedLdapServerContextSourceFactoryBean contextSourceFactoryBean =
//      EmbeddedLdapServerContextSourceFactoryBean.fromEmbeddedLdapServer();
//    contextSourceFactoryBean.setPort(0);
//    return contextSourceFactoryBean;
//  }
  @Bean
  public ContextSource contextSource(){
    LdapContextSource ldapContextSource = new LdapContextSource();
    ldapContextSource.setUrl("ldap://localhost:8389");
    ldapContextSource.setBase("dc=example,dc=org");
    ldapContextSource.setUserDn("cn=admin,dc=example,dc=org");
    ldapContextSource.setPassword("admin");
    return ldapContextSource;
  }

//  @Bean
//  UnboundIdContainer ldapContainer() {
//    return new UnboundIdContainer("dc=springframework,dc=org",
//      "classpath:users.ldif");
//  }

  @Bean
  LdapAuthoritiesPopulator authorities(BaseLdapPathContextSource contextSource) {
    String groupSearchBase = "ou=groups";
    DefaultLdapAuthoritiesPopulator authorities = new DefaultLdapAuthoritiesPopulator
      (contextSource, groupSearchBase);
    authorities.setGroupSearchFilter("(member={0})");
    return authorities;
  }

  @Bean
  AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource,
                                              LdapAuthoritiesPopulator authorities) {
    LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(contextSource,new BCryptPasswordEncoder());
    factory.setUserDnPatterns("uid={0},ou=people");
    factory.setPasswordAttribute("userPassword");
    return factory.createAuthenticationManager();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

    httpSecurity
      .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry.anyRequest().authenticated())
      .formLogin(t -> {
        t.successHandler((request, response, authentication) -> {
          System.out.println(authentication.getPrincipal());
          response.sendRedirect("/");
        });
      });
    return httpSecurity.build();
  }
}
