package com.ejemplo.resetdemo;

import java.time.LocalDateTime;

public class OtpChallenge {

    private final String email;
    private final String action;
    private final String code;
    private final LocalDateTime expiresAt;
    private int attempts;
    private boolean used;

    public OtpChallenge(String email, String action, String code, LocalDateTime expiresAt) {
        this.email = email;
        this.action = action;
        this.code = code;
        this.expiresAt = expiresAt;
        this.attempts = 0;
        this.used = false;
    }

    public String getEmail() {
        return email;
    }

    public String getAction() {
        return action;
    }

    public String getCode() {
        return code;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public int getAttempts() {
        return attempts;
    }

    public boolean isUsed() {
        return used;
    }

    public void incrementAttempts() {
        this.attempts++;
    }

    public void markUsed() {
        this.used = true;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public boolean hasAttemptsAvailable(int maxAttempts) {
        return attempts < maxAttempts;
    }
}
