package com.ejemplo.resetdemo;

import java.time.LocalDateTime;

public class Token {

    private String value;
    private String email;
    private LocalDateTime expiration;
    private boolean used;

    public Token(String value, String email) {
        this.value = value;
        this.email = email;
        this.expiration = LocalDateTime.now().plusMinutes(15);
        this.used = false;
    }

    public String getValue() { return value; }
    public String getEmail() { return email; }
    public LocalDateTime getExpiration() { return expiration; }
    public boolean isUsed() { return used; }
    public void setUsed(boolean used) { this.used = used; }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiration);
    }
}