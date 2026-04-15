package com.ejemplo.resetdemo;

import java.time.LocalDateTime;

public class VerifiedActionTicket {

    private final String ticket;
    private final String email;
    private final String action;
    private final LocalDateTime expiresAt;
    private boolean used;

    public VerifiedActionTicket(String ticket, String email, String action, LocalDateTime expiresAt) {
        this.ticket = ticket;
        this.email = email;
        this.action = action;
        this.expiresAt = expiresAt;
        this.used = false;
    }

    public String getTicket() {
        return ticket;
    }

    public String getEmail() {
        return email;
    }

    public String getAction() {
        return action;
    }

    public boolean isUsed() {
        return used;
    }

    public void markUsed() {
        this.used = true;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}
