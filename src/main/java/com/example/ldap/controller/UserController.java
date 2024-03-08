package com.example.ldap.controller;

import com.example.ldap.LdapUser;
import com.example.ldap.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

  @Autowired
  private UserService userService;

  @PostMapping("add")
  public ResponseEntity<HttpStatus> addUser(@RequestBody LdapUser user){
    userService.addUser(user);
    return new ResponseEntity<>(HttpStatus.CREATED);
  }

  @GetMapping("/all")
  public ResponseEntity<List<LdapUser>> getALlUser(){
    return new ResponseEntity<>(userService.getAllUsers(),HttpStatus.OK);
  }

}
