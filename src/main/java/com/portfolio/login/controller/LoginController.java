package com.portfolio.login.controller;

import com.portfolio.login.dto.JwtResponseDTO;
import com.portfolio.login.dto.UserDTO;
import com.portfolio.login.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserDTO userDTO){
        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userDTO.getEmail(),userDTO.getPassword()));

        String token = jwtUtil.generateToken(userDTO.getEmail());
        return ResponseEntity.ok(new JwtResponseDTO(token));
    }

    @GetMapping("/signup")
    public String login2(){
        return "Hello";
    }
}
