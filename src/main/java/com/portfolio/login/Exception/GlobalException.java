package com.portfolio.login.Exception;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalException {
        @ExceptionHandler(AuthenticationException.class)
        public ResponseEntity<String> handleAuthenticationException(AuthenticationException ex) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

}
