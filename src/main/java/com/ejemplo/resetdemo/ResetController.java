package com.ejemplo.resetdemo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class ResetController {

    private final TokenService tokenService;
    private final UserService userService;
    private final RateLimitService rateLimitService;
    private final SessionService sessionService;
    private final AuditService auditService;
    private final EmailService emailService;

    @Value("${app.base-url:http://localhost:8080}")
    private String baseUrl;

    public ResetController(TokenService tokenService,
                           UserService userService,
                           RateLimitService rateLimitService,
                           SessionService sessionService,
                           AuditService auditService,
                           EmailService emailService) {
        this.tokenService = tokenService;
        this.userService = userService;
        this.rateLimitService = rateLimitService;
        this.sessionService = sessionService;
        this.auditService = auditService;
        this.emailService = emailService;
    }

    @GetMapping("/")
    public String loginForm() {
        return "login";
    }

    @GetMapping("/register")
    public String registerForm() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String email,
                           @RequestParam String password,
                           @RequestParam String confirmPassword,
                           HttpServletRequest request,
                           Model model) {
        String normalizedUsername = normalizeUsername(username);
        String normalizedEmail = normalize(email);
        String ip = resolveIp(request);
        String userAgent = request.getHeader("User-Agent");

        if (normalizedUsername.isBlank() || normalizedEmail.isBlank()) {
            model.addAttribute("message", "Usuario y correo son obligatorios.");
            return "message";
        }

        if (!password.equals(confirmPassword)) {
            model.addAttribute("message", "Las contraseñas no coinciden.");
            return "message";
        }

        if (!validPassword(password)) {
            model.addAttribute("message", "La contraseña debe tener mínimo 12 caracteres, mayúscula, minúscula, número y símbolo.");
            return "message";
        }

        if (!userService.register(normalizedUsername, normalizedEmail, password)) {
            auditService.log(normalizedEmail, ip, userAgent, "REGISTER", "FALLO_USUARIO_O_CORREO_EN_USO");
            model.addAttribute("message", "Usuario o correo ya registrado.");
            return "message";
        }

        auditService.log(normalizedEmail, ip, userAgent, "REGISTER", "EXITO");
        model.addAttribute("message", "Registro exitoso. Ahora inicia sesión.");
        return "message";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletRequest request,
                        HttpSession session,
                        Model model) {

        String normalizedUsername = normalizeUsername(username);
        String email = userService.getEmailByUsername(normalizedUsername);
        String normalizedEmail = email != null ? email : "desconocido";
        String ip = resolveIp(request);
        String userAgent = request.getHeader("User-Agent");

        if (userService.authenticateByUsername(normalizedUsername, password)) {
            session.setAttribute("user", normalizedUsername);
            session.setAttribute("email", email);
            sessionService.registerSession(normalizedEmail, session);
            auditService.log(normalizedEmail, ip, userAgent, "LOGIN", "EXITO");
            model.addAttribute("username", normalizedUsername);
            return "home";
        }

        auditService.log(normalizedEmail, ip, userAgent, "LOGIN", "FALLO");
        model.addAttribute("message", "Credenciales inválidas.");
        return "message";
    }

    @GetMapping("/home")
    public String home(HttpSession session, Model model) {
        Object username = session.getAttribute("user");
        if (username == null) {
            model.addAttribute("message", "Debes iniciar sesión.");
            return "message";
        }
        model.addAttribute("username", username.toString());
        return "home";
    }

    @GetMapping("/forgot-password")
    public String forgotForm() {
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestParam String email,
                                 HttpServletRequest request,
                                 Model model) {
        String normalizedEmail = normalize(email);
        String ip = resolveIp(request);
        String userAgent = request.getHeader("User-Agent");

        boolean allowed = rateLimitService.isAllowed(normalizedEmail, ip);
        if (!allowed) {
            auditService.log(normalizedEmail, ip, userAgent, "PASSWORD_RESET_REQUEST", "BLOQUEADO_RATE_LIMIT");
            model.addAttribute("message", "Si el correo existe, se enviará un token de restablecimiento.");
            return "message";
        }

        boolean activeKnownAccount = userService.exists(normalizedEmail) && userService.isActive(normalizedEmail);
        if (activeKnownAccount) {
            String token = tokenService.generateToken(normalizedEmail);
            try {
                emailService.sendResetToken(normalizedEmail, token, baseUrl + "/reset");
                auditService.log(normalizedEmail, ip, userAgent, "PASSWORD_RESET_REQUEST", "EXITO");
            } catch (Exception ex) {
                auditService.log(normalizedEmail, ip, userAgent, "PASSWORD_RESET_REQUEST", "FALLO_ENVIO_CORREO");
                System.err.println("[MAIL ERROR] " + ex.getMessage());
                model.addAttribute("message", "No se pudo enviar el token por correo. Verifica la configuracion SMTP.");
                model.addAttribute("showResetLink", false);
                return "message";
            }
        } else {
            auditService.log(normalizedEmail, ip, userAgent, "PASSWORD_RESET_REQUEST", "FALLO_CUENTA_NO_VALIDA");
        }

        model.addAttribute("message", "Si el correo existe, se enviará un token de restablecimiento.");
        model.addAttribute("showResetLink", true);
        return "message";
    }

    @GetMapping("/reset")
    public String resetForm(@RequestParam(required = false) String token, Model model) {
        model.addAttribute("token", token == null ? "" : token);
        return "reset";
    }

    @PostMapping("/reset")
    public String resetPassword(
            @RequestParam String token,
            @RequestParam String newPassword,
            @RequestParam String confirmPassword,
            HttpServletRequest request,
            Model model) {

        String normalizedToken = token == null ? "" : token.trim();

        Token t = tokenService.getToken(normalizedToken);
        String ip = resolveIp(request);
        String userAgent = request.getHeader("User-Agent");
        String emailForAudit = t != null ? t.getEmail() : "desconocido";

        if (t == null) {
            auditService.log(emailForAudit, ip, userAgent, "PASSWORD_RESET_CONFIRM", "FALLO_TOKEN_INVALIDO");
            model.addAttribute("message", "Token inválido o expirado.");
            return "message";
        }

        if (t.isExpired()) {
            auditService.log(t.getEmail(), ip, userAgent, "PASSWORD_RESET_CONFIRM", "FALLO_TOKEN_EXPIRADO");
            model.addAttribute("message", "Token inválido o expirado.");
            return "message";
        }

        if (t.isUsed()) {
            auditService.log(t.getEmail(), ip, userAgent, "PASSWORD_RESET_CONFIRM", "FALLO_TOKEN_USADO");
            model.addAttribute("message", "Token inválido o expirado.");
            return "message";
        }

        if (!newPassword.equals(confirmPassword)) {
            auditService.log(t.getEmail(), ip, userAgent, "PASSWORD_RESET_CONFIRM", "FALLO_CONFIRMACION");
            model.addAttribute("message", "Las contraseñas no coinciden.");
            return "message";
        }

        if (!validPassword(newPassword)) {
            auditService.log(t.getEmail(), ip, userAgent, "PASSWORD_RESET_CONFIRM", "FALLO_POLITICA_PASSWORD");
            model.addAttribute("message", "La contraseña debe tener mínimo 12 caracteres, mayúscula, minúscula, número y símbolo.");
            return "message";
        }

        userService.updatePassword(t.getEmail(), newPassword);
        HttpSession currentSession = request.getSession(false);
        String keepSessionId = currentSession != null ? currentSession.getId() : null;
        sessionService.invalidateAll(t.getEmail(), keepSessionId);
        t.setUsed(true);
        tokenService.revokeToken(normalizedToken);
        auditService.log(t.getEmail(), ip, userAgent, "PASSWORD_RESET_CONFIRM", "EXITO");

        model.addAttribute("message", "Contraseña actualizada correctamente");
        return "message";
    }

    private String normalize(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private String normalizeUsername(String username) {
        return username == null ? "" : username.trim().toLowerCase();
    }

    private String resolveIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private boolean validPassword(String password) {
        if (password == null) {
            return false;
        }
        return password.length() >= 12
                && password.matches(".*[A-Z].*")
                && password.matches(".*[a-z].*")
                && password.matches(".*[0-9].*")
                && password.matches(".*[!@#$%^&*()].*");
    }
}