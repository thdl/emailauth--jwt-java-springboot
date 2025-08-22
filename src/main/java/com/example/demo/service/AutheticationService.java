package com.example.demo.service;

import com.example.demo.dto.LoginUserDto;
import com.example.demo.dto.RegisterUSerDto;
import com.example.demo.dto.VerifyUserDto;
import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import jakarta.mail.MessagingException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Random;

@Service
public class AutheticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager autheticationManager;
    private final EmailService emailService;

    public AutheticationService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager autheticationManager,
            EmailService emailService

    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.autheticationManager = autheticationManager;
        this.emailService = emailService;

    }

    public User signup(RegisterUSerDto input) {
        User user = new User(input.getUsername(), input.getEmail(),passwordEncoder.encode(input.getPassword()));
        user.setVerificationCode(generateVerificationCode());
        user.setVerificationexpiresat(LocalDateTime.now().plusMinutes(15));
        user.setEnabeld(false);
        sendVerificationEmail(user);
        return userRepository.save(user);
    }

    public User authenticate(LoginUserDto input) {
        User user = userRepository.findByEmail(input.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (!user.isEnabeld()) {
            throw  new RuntimeException("Account not verified, Please verify the account");
        }
        autheticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        input.getEmail(),
                        input.getPassword()
                )
        );
        return user;
    }
    public void verifyUser(VerifyUserDto input) {
        Optional<User> optionalUser = userRepository.findByEmail(input.getEmail());
        if (optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (user.isEnabeld()) {
                throw new RuntimeException("User is already verified");
            }

            if (user.getVerificationexpiresat().isBefore(LocalDateTime.now())) {
                throw new RuntimeException("Verification code is expired");
            }

            if (user.getVerificationCode().equals(optionalUser.get().verificationCode)) {
                user.setEnabeld(true);
                user.setVerificationCode(null);
                user.setVerificationexpiresat(null);
                userRepository.save(user);
            } else {
                throw new RuntimeException("Invalid verification code");

            }
        } else {
            throw new RuntimeException("User not found");
        }
    }
    public void resendVerificationCode(String email) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        System.out.println(email);
        if(optionalUser.isPresent()) {
            User user = optionalUser.get();
            if (user.isEnabeld()) {
                throw new RuntimeException("Account is already verified");
            }
            user.setVerificationCode(generateVerificationCode());
            user.setVerificationexpiresat(LocalDateTime.now().plusHours(1));
            sendVerificationEmail(user);
            userRepository.save(user);
        } else {
            throw new RuntimeException("User not found");
        }
    }

    public void sendVerificationEmail(User user) {
        String subject = "Account Verification";
        String verificationCode = user.getVerificationCode();
        String htmlMessage = "<html>"
                + "<body style=\"font-family: Arial, sans-serif;\">"
                + "<div style=\"background-color: #f5f5f5; padding: 20px;\">"
                + "<h2 style=\"color: #333;\">Welcome to our app!</h2>"
                + "<p style=\"font-size: 16px;\">Please enter the verification code below to continue:</p>"
                + "<div style=\"background-color: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1);\">"
                + "<h3 style=\"color: #333;\">Verification Code:</h3>"
                + "<p style=\"font-size: 18px; font-weight: bold; color: #007bff;\">" + verificationCode + "</p>"
                + "</div>"
                + "</div>"
                + "</body>"
                + "</html>";

        try {
            emailService.sendVerificationEmail(user.getEmail(), subject,htmlMessage);
        } catch (MessagingException e) {
            e.printStackTrace();
        }

    }
    private String generateVerificationCode() {
        Random random = new Random();
        int code = random.nextInt(900000) + 100000;
        return String.valueOf(code);
    }
}

