package com.ejemplo.resetdemo;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class OtpService {

    private static final int OTP_LENGTH = 6;
    private static final int OTP_EXPIRATION_MINUTES = 5;
    private static final int MAX_ATTEMPTS = 3;
    private static final int VERIFIED_TICKET_EXPIRATION_MINUTES = 10;

    private final Map<String, OtpChallenge> challengeByEmailAndAction = new HashMap<>();
    private final Map<String, VerifiedActionTicket> verifiedTickets = new HashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    public enum ValidationStatus {
        VALID,
        INVALID_CODE,
        EXPIRED,
        USED,
        ATTEMPTS_EXCEEDED,
        NOT_FOUND
    }

    public record ValidationResult(ValidationStatus status, String verifiedTicket) {
    }

    public synchronized String createChallenge(String email, String action) {
        cleanupExpiredData();
        String key = challengeKey(email, action);
        String code = generateOtpCode();
        OtpChallenge challenge = new OtpChallenge(email, action, code, LocalDateTime.now().plusMinutes(OTP_EXPIRATION_MINUTES));
        challengeByEmailAndAction.put(key, challenge);
        return code;
    }

    public synchronized ValidationResult validateCode(String email, String action, String code) {
        cleanupExpiredData();
        OtpChallenge challenge = challengeByEmailAndAction.get(challengeKey(email, action));
        if (challenge == null) {
            return new ValidationResult(ValidationStatus.NOT_FOUND, null);
        }

        if (challenge.isUsed()) {
            return new ValidationResult(ValidationStatus.USED, null);
        }

        if (challenge.isExpired()) {
            return new ValidationResult(ValidationStatus.EXPIRED, null);
        }

        if (!challenge.hasAttemptsAvailable(MAX_ATTEMPTS)) {
            return new ValidationResult(ValidationStatus.ATTEMPTS_EXCEEDED, null);
        }

        if (!challenge.getCode().equals(normalizeCode(code))) {
            challenge.incrementAttempts();
            if (!challenge.hasAttemptsAvailable(MAX_ATTEMPTS)) {
                return new ValidationResult(ValidationStatus.ATTEMPTS_EXCEEDED, null);
            }
            return new ValidationResult(ValidationStatus.INVALID_CODE, null);
        }

        challenge.markUsed();
        String ticket = generateVerificationTicket();
        verifiedTickets.put(ticket, new VerifiedActionTicket(
                ticket,
                challenge.getEmail(),
                challenge.getAction(),
                LocalDateTime.now().plusMinutes(VERIFIED_TICKET_EXPIRATION_MINUTES)
        ));
        return new ValidationResult(ValidationStatus.VALID, ticket);
    }

    public synchronized boolean consumeVerifiedTicket(String ticket, String email, String action) {
        cleanupExpiredData();
        if (ticket == null || ticket.isBlank()) {
            return false;
        }

        VerifiedActionTicket verifiedTicket = verifiedTickets.get(ticket.trim());
        if (verifiedTicket == null || verifiedTicket.isUsed() || verifiedTicket.isExpired()) {
            return false;
        }

        if (!verifiedTicket.getEmail().equals(email) || !verifiedTicket.getAction().equals(action)) {
            return false;
        }

        verifiedTicket.markUsed();
        return true;
    }

    private String generateOtpCode() {
        int bound = (int) Math.pow(10, OTP_LENGTH);
        int number = secureRandom.nextInt(bound);
        return String.format("%0" + OTP_LENGTH + "d", number);
    }

    private String generateVerificationTicket() {
        String raw = UUID.randomUUID().toString() + ":" + System.nanoTime();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes());
    }

    private String challengeKey(String email, String action) {
        return normalize(email) + "|" + normalize(action);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase();
    }

    private String normalizeCode(String value) {
        return value == null ? "" : value.replaceAll("\\s+", "").trim();
    }

    private void cleanupExpiredData() {
        challengeByEmailAndAction.entrySet().removeIf(entry -> {
            OtpChallenge challenge = entry.getValue();
            return challenge.isExpired() || challenge.isUsed();
        });

        verifiedTickets.entrySet().removeIf(entry -> {
            VerifiedActionTicket ticket = entry.getValue();
            return ticket.isExpired() || ticket.isUsed();
        });
    }
}
