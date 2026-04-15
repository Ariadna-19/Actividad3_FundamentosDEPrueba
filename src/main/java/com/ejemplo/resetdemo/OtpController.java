package com.ejemplo.resetdemo;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/sensitive-actions")
public class OtpController {

    private static final String ACTION_CHANGE_PASSWORD = "CHANGE_PASSWORD";

    private final UserService userService;
    private final OtpService otpService;
    private final EmailService emailService;
    private final AuditService auditService;

    public OtpController(UserService userService,
                         OtpService otpService,
                         EmailService emailService,
                         AuditService auditService) {
        this.userService = userService;
        this.otpService = otpService;
        this.emailService = emailService;
        this.auditService = auditService;
    }

    @PostMapping("/otp/request")
    public ResponseEntity<ApiResponse> requestOtp(@RequestBody OtpRequest request, HttpServletRequest httpRequest) {
        String email = normalize(request.email());
        String action = normalizeAction(request.action());
        String ip = resolveIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        if (email.isBlank() || action.isBlank()) {
            return ResponseEntity.badRequest().body(new ApiResponse("EMAIL_Y_ACCION_REQUERIDOS", null));
        }

        if (!userService.exists(email) || !userService.isActive(email)) {
            auditService.log(email, ip, userAgent, "OTP_REQUEST", "FALLO_CUENTA_NO_VALIDA");
            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .body(new ApiResponse("SI_LA_CUENTA_EXISTE_SE_ENVIO_UN_OTP", null));
        }

        String otpCode = otpService.createChallenge(email, action);

        try {
            emailService.sendOtpCode(email, otpCode, action);
            auditService.log(email, ip, userAgent, "OTP_REQUEST", "EXITO");
        } catch (Exception ex) {
            auditService.log(email, ip, userAgent, "OTP_REQUEST", "FALLO_ENVIO_CORREO");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse("NO_SE_PUDO_ENVIAR_EL_OTP", null));
        }

        return ResponseEntity.ok(new ApiResponse("OTP_ENVIADO", null));
    }

    @PostMapping("/otp/validate")
    public ResponseEntity<ApiResponse> validateOtp(@RequestBody OtpValidationRequest request, HttpServletRequest httpRequest) {
        String email = normalize(request.email());
        String action = normalizeAction(request.action());
        String code = request.code();
        String ip = resolveIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        if (email.isBlank() || action.isBlank() || code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(new ApiResponse("EMAIL_ACCION_Y_CODIGO_REQUERIDOS", null));
        }

        OtpService.ValidationResult validationResult = otpService.validateCode(email, action, code);
        OtpService.ValidationStatus status = validationResult.status();

        if (status == OtpService.ValidationStatus.VALID) {
            auditService.log(email, ip, userAgent, "OTP_VALIDATE", "EXITO");
            return ResponseEntity.ok(new ApiResponse("OTP_VALIDO", validationResult.verifiedTicket()));
        }

        auditService.log(email, ip, userAgent, "OTP_VALIDATE", "FALLO_" + status.name());

        if (status == OtpService.ValidationStatus.ATTEMPTS_EXCEEDED) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(new ApiResponse("LIMITE_DE_INTENTOS_SUPERADO", null));
        }

        if (status == OtpService.ValidationStatus.EXPIRED) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("OTP_EXPIRADO", null));
        }

        if (status == OtpService.ValidationStatus.USED) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ApiResponse("OTP_REUTILIZADO", null));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse("OTP_INVALIDO", null));
    }

    @PostMapping("/password/change-with-otp")
    public ResponseEntity<ApiResponse> changePasswordWithOtpVerification(@RequestBody ChangePasswordRequest request,
                                                                         HttpServletRequest httpRequest) {
        String email = normalize(request.email());
        String currentPassword = request.currentPassword();
        String newPassword = request.newPassword();
        String verificationTicket = request.verificationTicket();
        String ip = resolveIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        if (email.isBlank() || currentPassword == null || newPassword == null || verificationTicket == null) {
            return ResponseEntity.badRequest().body(new ApiResponse("DATOS_INCOMPLETOS", null));
        }

        if (!userService.authenticateByEmail(email, currentPassword)) {
            auditService.log(email, ip, userAgent, "CHANGE_PASSWORD_WITH_OTP", "FALLO_CREDENCIALES");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse("CREDENCIALES_INVALIDAS", null));
        }

        if (!validPassword(newPassword)) {
            auditService.log(email, ip, userAgent, "CHANGE_PASSWORD_WITH_OTP", "FALLO_POLITICA_PASSWORD");
            return ResponseEntity.badRequest()
                    .body(new ApiResponse("PASSWORD_NO_CUMPLE_POLITICA", null));
        }

        boolean verified = otpService.consumeVerifiedTicket(
                verificationTicket,
                email,
                ACTION_CHANGE_PASSWORD
        );

        if (!verified) {
            auditService.log(email, ip, userAgent, "CHANGE_PASSWORD_WITH_OTP", "FALLO_VERIFICACION_OTP");
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ApiResponse("VERIFICACION_OTP_REQUERIDA", null));
        }

        userService.updatePassword(email, newPassword);
        auditService.log(email, ip, userAgent, "CHANGE_PASSWORD_WITH_OTP", "EXITO");
        return ResponseEntity.ok(new ApiResponse("PASSWORD_ACTUALIZADA", null));
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase();
    }

    private String normalizeAction(String value) {
        if (value == null || value.isBlank()) {
            return "";
        }
        return value.trim().toUpperCase();
    }

    private String resolveIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private boolean validPassword(String password) {
        return password != null
                && password.length() >= 12
                && password.matches(".*[A-Z].*")
                && password.matches(".*[a-z].*")
                && password.matches(".*[0-9].*")
                && password.matches(".*[!@#$%^&*()].*");
    }

    public record OtpRequest(String email, String action) {
    }

    public record OtpValidationRequest(String email, String action, String code) {
    }

    public record ChangePasswordRequest(String email,
                                        String currentPassword,
                                        String newPassword,
                                        String verificationTicket) {
    }

    public record ApiResponse(String message, String verificationTicket) {
    }
}
