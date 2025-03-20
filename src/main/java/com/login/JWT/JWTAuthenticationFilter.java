package com.login.JWT;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.login.JWTService.JWTService;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
    @Autowired
    private JWTService jwtService;
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        System.out.println("Inside do filter method..........");
        String token = null;
        String userName = null;

        String authorizationHeader = request.getHeader("Authorization");
        System.out.println(authorizationHeader);

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer")) {
            token = authorizationHeader.substring(7);
            userName = jwtService.extractUsername(token);
        }

        // Cookie[] cookies = request.getCookies();
        // if (cookies != null) {
        // for (Cookie cookie : cookies) {
        // if ("accessToken".equals(cookie.getName())) {
        // token = cookie.getValue();
        // break;
        // }
        // }
        // }
        System.out.println("token inside do - filter Method: " + token);

        if (token != null) {
            userName = jwtService.extractUsername(token);
            System.out.println(userName);

        }
        if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
            if (jwtService.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                 System.out.println("auth token set to the security context");
                SecurityContextHolder.getContext().setAuthentication(authToken);
            } else {
                System.out.println("else part");
            }
        }
        System.out.println("proceed to nxt");
        filterChain.doFilter(request, response);
    }

}
