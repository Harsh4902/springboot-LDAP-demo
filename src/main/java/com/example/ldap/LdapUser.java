package com.example.ldap;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;

public class LdapUser {

  private String cn;
  private String sn;
  private String userName;
  private String password;

  public String getCn() {
    return cn;
  }

  public void setCn(String cn) {
    this.cn = cn;
  }

  public String getSn() {
    return sn;
  }

  public void setSn(String sn) {
    this.sn = sn;
  }

  public String getUserName() {
    return userName;
  }

  public void setUserName(String userName) {
    this.userName = userName;
  }

  public String getPassword() {
    return password;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public Attributes toAttribute(){
    Attributes attributes = new BasicAttributes();
    attributes.put("objectClass","inetOrgPerson");
    attributes.put("cn",cn);
    attributes.put("sn", sn);
    attributes.put("uid", userName);
    attributes.put("userPassword", new BCryptPasswordEncoder().encode(password));

    return attributes;
  }
}
