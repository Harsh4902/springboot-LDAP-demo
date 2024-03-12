package com.example.ldap.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class DBUser {

  @Id
  @GeneratedValue(strategy = GenerationType.AUTO)
  private long id;

  private String uid;

  public DBUser() {
  }

  public DBUser(long id, String uid) {
    this.id = id;
    this.uid = uid;
  }

  public long getId() {
    return id;
  }

  public void setId(long id) {
    this.id = id;
  }

  public String getUid() {
    return uid;
  }

  public void setUid(String uid) {
    this.uid = uid;
  }
}
