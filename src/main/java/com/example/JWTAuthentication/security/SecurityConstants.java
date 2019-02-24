package com.example.JWTAuthentication.security;

public class SecurityConstants {
    public static final String SECRET = "secre";
    public static final String PREFIX_TOKEN = "Bearer ";
    public static final String HEADER_KEY = "Authorization";
    public static final long EXPIRATION_TIME = 864_000_000L; // 10 dia
}

