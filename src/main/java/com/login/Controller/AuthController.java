package com.login.Controller;

import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.login.JWTService.JWTService;

@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
@RestController
public class AuthController {

    @Autowired
    private JWTService jwtService;

    @GetMapping("/getToken")
    public ResponseEntity<?> getTokenFromCookie(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                System.out.println(cookie.getName());
                if ("refreshToken".equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                    break;
                }
            }
        }

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("message", "Token not found"));
        }

        try {
            jwtService.isTokenExpired(refreshToken);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Refresh token expired"));
        }
        String newAccessToken = jwtService.generateAccessToken(jwtService.extractUsername(refreshToken));
        Cookie accessTokenCookie = new Cookie("jwtToken", newAccessToken);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setSecure(true);
        accessTokenCookie.setMaxAge(jwtService.getAccessTokenDuration());

        response.addCookie(accessTokenCookie);
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }

    @GetMapping("/checkCookie")
    public ResponseEntity<Void> checkCookieExists(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return ResponseEntity.status(HttpStatus.OK).build();
                }
            }
        }

        return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
    }

}
