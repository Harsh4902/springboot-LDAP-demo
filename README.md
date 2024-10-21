* Basic Url configuration for LDAP server connection:
```
spring.ldap.url=ldap://192.168.12.55:389
spring.ldap.base=dc=example,dc=org
spring.ldap.username=admin
spring.ldap.password=sttl@321
spring.ldap.embedded.validation.enabled=false
```
* ContextSource bean for which is configured to make LDAP connection for any Search/Add/Remove Request:
```
@Bean
public ContextSource contextSource(){
  LdapContextSource ldapContextSource = new LdapContextSource() ;
  ldapContextSource.setUrl("ldap://192.168.12.55:389");
  ldapContextSource.setBase("dc=example,dc=com");
  ldapContextSource.setUserDn("cn=admin,dc=example,dc=com");
  ldapContextSource.setPassword("sttl@321");
  return ldapContextSource;
}
```
* AuthenticationManager which will help to make authentication through LDAP server:
```
@Bean
AuthenticationManager authenticationManager(BaseLdapPathContextSource contextSource,
  LdapAuthoritiesPopulator authorities) {
  LdapPasswordComparisonAuthenticationManagerFactory factory = new LdapPasswordComparisonAuthenticationManagerFactory(contextSource,new BCryptPasswordEncoder());
  factory.setUserDnPatterns("uid={0}");
  factory.setPasswordAttribute("userPassword");
  return factory.createAuthenticationManager();
}
```

These are the basic setups which can be modified based on the LDAP server configuration.
