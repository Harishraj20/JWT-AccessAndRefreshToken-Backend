package com.login.Controller;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.login.DTO.RefreshTokenRequest;
import com.login.JWTService.JWTService;
import com.login.Model.User;

@RestController
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class LoginController {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/loginuser")

    public ResponseEntity<?> userLogin(@RequestBody User user, HttpServletResponse response) {
        try {
            @SuppressWarnings("unused")
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword()));

            String accessToken = jwtService.generateAccessToken(user.getEmail());
            String refreshToken = jwtService.generateRefreshToken(user.getEmail());

            HashMap<String, String> map = new HashMap<>();
            map.put("accessToken", accessToken);
            map.put("refreshToken", refreshToken);

            Cookie accessTokenCookie = new Cookie("jwtToken", accessToken);
            accessTokenCookie.setHttpOnly(true);
            accessTokenCookie.setPath("/");
            accessTokenCookie.setSecure(true);
            accessTokenCookie.setMaxAge(jwtService.getAccessTokenDuration());

            response.addCookie(accessTokenCookie);

            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setMaxAge(jwtService.getRefreshTokenDuration());
            response.addCookie(refreshTokenCookie);

            return ResponseEntity.ok(map);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("msg", e.getMessage()));
        }
    }

    @GetMapping("/users/hello")
    public String protectedEndPoint1() {
        return "Hello";
    }

    @GetMapping("/users/welcome")
    public String protectedEndPoint2() {
        return "Welcome";
    }

    @GetMapping("/users/lunch")
    public String protectedEndPoint3() {
        return "Have lunch";
    }

    @GetMapping("/users/peace")
    public String protectedEndPoint4() {

        return "Peace Bro";
    }

    @GetMapping("/remove/cookie")
    public String removeCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("jwtToken", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);

        return "success";
    }

    @GetMapping("/refreshToken")

    public ResponseEntity<?> generateRefreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        System.out.println("Im triggered....");
        String accessToken = refreshTokenRequest.getRefreshToken();
        System.out.println("The token retrieved: " + accessToken);
        if (jwtService.isTokenExpired(accessToken)) {
            return ResponseEntity.status(401).body("Refresh token expired");
        }
        String userName = jwtService.extractUsername(accessToken);
        String newAccessToken = jwtService.generateAccessToken(userName);
        System.out.println("user name: " + userName);

        return ResponseEntity.ok(Map.of("newAccessToken", newAccessToken));
    }
}
