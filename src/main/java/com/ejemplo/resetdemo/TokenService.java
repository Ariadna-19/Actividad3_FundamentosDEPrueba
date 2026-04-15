package com.ejemplo.resetdemo;

import java.util.HashMap;
import java.security.SecureRandom;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private final HashMap<String, Token> tokens = new HashMap<>();
    private final SecureRandom random = new SecureRandom();

    public String generateToken(String email) {
        String value = generateSixDigitToken();
        while (tokens.containsKey(value)) {
            value = generateSixDigitToken();
        }
        Token token = new Token(value, email);
        tokens.put(value, token);
        return value;
    }

    public Token getToken(String value) {
        return tokens.get(normalizeToken(value));
    }

    public void revokeToken(String value) {
        tokens.remove(normalizeToken(value));
    }

    private String generateSixDigitToken() {
        int number = 100000 + random.nextInt(900000);
        return String.valueOf(number);
    }

    private String normalizeToken(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("\\s+", "").trim();
    }
}