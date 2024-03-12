package com.example.ldap.entity;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DBUserRepository extends JpaRepository<DBUser,Long> {

  DBUser findByUid(String uid);

}
