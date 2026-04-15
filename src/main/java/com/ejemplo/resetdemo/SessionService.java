package com.ejemplo.resetdemo;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Service;

@Service
public class SessionService {

    private static class SessionRecord {
        private final String sessionId;
        private final HttpSession session;

        SessionRecord(String sessionId, HttpSession session) {
            this.sessionId = sessionId;
            this.session = session;
        }
    }

    private final Map<String, Set<SessionRecord>> sessionsByUser = new HashMap<>();

    public synchronized void registerSession(String email, HttpSession session) {
        Set<SessionRecord> sessions = sessionsByUser.computeIfAbsent(email, ignored -> new HashSet<>());
        sessions.add(new SessionRecord(session.getId(), session));
    }

    public synchronized void invalidateAll(String email, String keepSessionId) {
        Set<SessionRecord> sessions = sessionsByUser.get(email);
        if (sessions == null) {
            return;
        }

        Iterator<SessionRecord> iterator = sessions.iterator();
        while (iterator.hasNext()) {
            SessionRecord record = iterator.next();
            if (keepSessionId == null || !record.sessionId.equals(keepSessionId)) {
                try {
                    record.session.invalidate();
                } catch (IllegalStateException ignored) {
                }
                iterator.remove();
            }
        }

        if (sessions.isEmpty()) {
            sessionsByUser.remove(email);
        }
    }
}
