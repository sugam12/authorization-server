package com.user.authorization.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@PreAuthorize("hasRole('ADMIN')")
@RestController
public class UserController {

    private final JdbcUserDetailsManager userDetailsManager;

    public UserController(JdbcUserDetailsManager userDetailsManager) {
        this.userDetailsManager = userDetailsManager;
    }

    @GetMapping("/users/{username}")
    UserDetails getUsers(@PathVariable String username) {
        return userDetailsManager.loadUserByUsername(username);
    }

    @GetMapping("/groups")
    List<String> getGroups() {
        return userDetailsManager.findAllGroups();
    }

    @GetMapping("/groups/{userName}/users")
    List<String> getUsersInGroups(@PathVariable String userName) {
        return userDetailsManager.findUsersInGroup(userName);
    }

    @GetMapping("/groups/{groupName}/authorities")
    List<GrantedAuthority> getGroupAuthorities(@PathVariable String groupName) {
        return userDetailsManager.findGroupAuthorities(groupName);
    }
    
}
