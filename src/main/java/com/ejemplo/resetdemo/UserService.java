package com.ejemplo.resetdemo;

import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private static class UserRecord {
        private String username;
        private String email;
        private String password;
        private boolean active;

        UserRecord(String username, String email, String password, boolean active) {
            this.username = username;
            this.email = email;
            this.password = password;
            this.active = active;
        }
    }

    private final Map<String, UserRecord> usersByEmail = new HashMap<>();
    private final Map<String, String> emailByUsername = new HashMap<>();

    public UserService() {
        register("ariadna", "ariadna@mail.com", "Password123!");
    }

    public synchronized boolean register(String username, String email, String password) {
        if (exists(email) || usernameExists(username)) {
            return false;
        }

        UserRecord user = new UserRecord(username, email, password, true);
        usersByEmail.put(email, user);
        emailByUsername.put(username, email);
        return true;
    }

    public boolean exists(String email) {
        return usersByEmail.containsKey(email);
    }

    public boolean usernameExists(String username) {
        return emailByUsername.containsKey(username);
    }

    public boolean isActive(String email) {
        UserRecord user = usersByEmail.get(email);
        return user != null && user.active;
    }

    public boolean authenticateByUsername(String username, String password) {
        String email = emailByUsername.get(username);
        if (email == null) {
            return false;
        }
        UserRecord user = usersByEmail.get(email);
        return user != null && user.active && user.password.equals(password);
    }

    public boolean authenticateByEmail(String email, String password) {
        UserRecord user = usersByEmail.get(email);
        return user != null && user.active && user.password.equals(password);
    }

    public String getEmailByUsername(String username) {
        return emailByUsername.get(username);
    }

    public synchronized void updatePassword(String email, String newPassword) {
        UserRecord user = usersByEmail.get(email);
        if (user == null) {
            return;
        }
        user.password = newPassword;
        user.active = true;
    }
}