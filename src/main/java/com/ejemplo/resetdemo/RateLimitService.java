package com.ejemplo.resetdemo;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class RateLimitService {

    private static final int MAX_REQUESTS_PER_HOUR = 5;
    private final Map<String, List<LocalDateTime>> attemptsByEmail = new HashMap<>();
    private final Map<String, List<LocalDateTime>> attemptsByIp = new HashMap<>();

    public synchronized boolean isAllowed(String email, String ip) {
        LocalDateTime now = LocalDateTime.now();
        List<LocalDateTime> emailRecords = attemptsByEmail.computeIfAbsent(email, ignored -> new ArrayList<>());
        List<LocalDateTime> ipRecords = attemptsByIp.computeIfAbsent(ip, ignored -> new ArrayList<>());

        cleanup(emailRecords, now);
        cleanup(ipRecords, now);

        if (emailRecords.size() >= MAX_REQUESTS_PER_HOUR || ipRecords.size() >= MAX_REQUESTS_PER_HOUR) {
            return false;
        }

        emailRecords.add(now);
        ipRecords.add(now);
        return true;
    }

    private void cleanup(List<LocalDateTime> records, LocalDateTime now) {
        Iterator<LocalDateTime> iterator = records.iterator();
        while (iterator.hasNext()) {
            LocalDateTime attempt = iterator.next();
            if (attempt.isBefore(now.minusHours(1))) {
                iterator.remove();
            }
        }
    }

}
