package com.example.demo.controller;

import com.example.demo.dto.LoginUserDto;
import com.example.demo.dto.RegisterUSerDto;
import com.example.demo.dto.VerifyUserDto;
import com.example.demo.model.User;
import com.example.demo.responses.LoginResponse;
import com.example.demo.service.AutheticationService;
import com.example.demo.service.JwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.login.AccountException;

@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private final JwtService jwtService;
    private final AutheticationService autheticationService;

    public AuthenticationController(JwtService jwtService, AutheticationService autheticationService) {
         this.jwtService = jwtService;
         this.autheticationService = autheticationService;
    }
    @PostMapping("/signup")
    public ResponseEntity<User> register(@RequestBody RegisterUSerDto registerUSerDto) {
        User registerUser = autheticationService.signup(registerUSerDto);
        return ResponseEntity.ok(registerUser);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticate(@RequestBody LoginUserDto loginUserDto) {
        User authenticatedUser = autheticationService.authenticate(loginUserDto);
        String jwtToken = jwtService.generateToken(authenticatedUser);
        LoginResponse loginResponse = new LoginResponse(jwtToken, jwtService.getExpirationtime());
        return ResponseEntity.ok(loginResponse);
    }
    @PostMapping("/verify")
    public ResponseEntity<?> verifyUser(@RequestBody VerifyUserDto verifyUserDto) {
        try {
            autheticationService.verifyUser(verifyUserDto);
            return ResponseEntity.ok("Account verified successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    @PostMapping("/resend")
    public ResponseEntity<?> resendVerificationCode(@RequestParam String email) {
        try {
            autheticationService.resendVerificationCode(email);
            return ResponseEntity.ok("Verification code sent");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
