package com.example.ldap.service;

import java.util.List;

import javax.naming.NamingException;
import javax.naming.Name;

import com.example.ldap.entity.LdapUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.stereotype.Service;


@Service
public class UserService {

  @Autowired
  private LdapTemplate ldapTemplate;
  private static final String BASE_DN = "ou=people";

  public void addUser(LdapUser ldapUser) {
    ldapTemplate.bind("uid=" + ldapUser.getUserName() + "," + BASE_DN, null, ldapUser.toAttribute());
  }

  public List<LdapUser> getAllUsers() {
    return ldapTemplate.search(BASE_DN, "(objectclass=inetOrgPerson)",
        (AttributesMapper<LdapUser>) attributes ->{
          LdapUser ldapuser = new LdapUser();
          ldapuser.setCn(attributes.get("cn").get().toString());
          ldapuser.setSn(attributes.get("sn").get().toString());
          ldapuser.setUserName(attributes.get("uid").get().toString());
          ldapuser.setPassword(attributes.get("userPassword").get().toString());
          return ldapuser;
        });
  }

  public String getUserById(String uid) {
    List<String> usernames = ldapTemplate.search(
        BASE_DN,
        "(uid=" + uid + ")",
        (AttributesMapper<String>) attrs -> {
          try {
            return (String) attrs.get("sn").get();
          } catch (NamingException e) {
            throw new RuntimeException(e);
          }
        }
    );

    if (!usernames.isEmpty()) {
      return usernames.get(0);
    } else {
      return null; // User not found
    }
  }
  public void deleteUser(String uid) {
    Name userDn= LdapNameBuilder.newInstance(BASE_DN)
        .add("uid",uid)
        .build();
    ldapTemplate.unbind(userDn);
  }
}
