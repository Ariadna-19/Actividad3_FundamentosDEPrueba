package com.ejemplo.resetdemo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.mail.from:no-reply@resetdemo.local}")
    private String from;

    @Value("${spring.mail.host:}")
    private String smtpHost;

    @Value("${app.mail.mock-enabled:false}")
    private boolean mockEnabled;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendResetToken(String to, String token, String resetPageUrl) {
        String subject = "Restablecimiento de contraseña";
        String text = "Recibimos una solicitud para restablecer tu contraseña.\n\n"
                + "Usa este token de un solo uso (expira en 15 minutos):\n"
                + token + "\n\n"
                + "Ingresa el token en la pantalla de restablecimiento: "
                + resetPageUrl + "\n\n"
                + "Si no solicitaste este cambio, ignora este mensaje.";
        sendMailOrMock(to, subject, text);
    }

    public void sendOtpCode(String to, String otpCode, String action) {
        String subject = "Codigo de verificacion";
        String text = "Recibimos una solicitud para la accion sensible: " + action + "\n\n"
                + "Tu codigo OTP (expira en 5 minutos) es:\n"
                + otpCode + "\n\n"
                + "Este codigo es de un solo uso y permite maximo 3 intentos."
                + "\n\nSi no solicitaste esta accion, ignora este mensaje.";

        sendMailOrMock(to, subject, text);
    }

    private void sendMailOrMock(String to, String subject, String text) {
        if (mockEnabled) {
            printMockMail(to, subject, text);
            return;
        }

        if (smtpHost == null || smtpHost.isBlank()) {
            throw new IllegalStateException("SMTP no configurado. Define MAIL_HOST y credenciales o activa MAIL_MOCK_ENABLED=true para pruebas locales.");
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);
        mailSender.send(message);
    }

    private void printMockMail(String to, String subject, String text) {
        System.out.println("[MAIL MOCK] to=" + to + " | subject=" + subject + "\n" + text);
    }
}
