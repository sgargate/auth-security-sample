package com.example.springauthserver;


public record AuthRequest(
    String email,
    String password,
    String pan,
    String mobileNumber,
    String otp,
    String otpToken
) {

}
