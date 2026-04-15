package com.ejemplo.resetdemo;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class AuditService {

    public static class AuditRecord {
        private final LocalDateTime timestamp;
        private final String email;
        private final String ip;
        private final String userAgent;
        private final String event;
        private final String result;

        AuditRecord(String email, String ip, String userAgent, String event, String result) {
            this.timestamp = LocalDateTime.now();
            this.email = email;
            this.ip = ip;
            this.userAgent = userAgent;
            this.event = event;
            this.result = result;
        }

        @Override
        public String toString() {
            return "[AUDIT] " + timestamp + " | event=" + event + " | email=" + email + " | ip=" + ip
                    + " | ua=" + userAgent + " | result=" + result;
        }
    }

    private final List<AuditRecord> records = new ArrayList<>();

    public synchronized void log(String email, String ip, String userAgent, String event, String result) {
        AuditRecord record = new AuditRecord(email, ip, userAgent, event, result);
        records.add(record);
        System.out.println(record);
    }
}
