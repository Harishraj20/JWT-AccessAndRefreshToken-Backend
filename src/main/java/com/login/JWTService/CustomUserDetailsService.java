package com.login.JWTService;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.login.Model.Principal;
import com.login.Model.User;

public class CustomUserDetailsService implements UserDetailsService{

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(username.equals("test@example.com")){
            User user = new User();
            user.setEmail("test@example.com");
            user.setPassword("{noop}123");
            return new Principal(user);
        }
        throw new UsernameNotFoundException("Incorrect email Id!");
       
    }
    
}
