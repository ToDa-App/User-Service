package com.toda.User_Service.exception;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiGenericResponse<Object>> handleValidationErrors(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error -> {
            errors.put(error.getField(), error.getDefaultMessage());
        });
        ApiGenericResponse<Object> response = ApiGenericResponse.error("Validation failed", errors);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiGenericResponse<Object>> handleResponseStatusException(ResponseStatusException ex) {
        Map<String, String> errors = new HashMap<>();
        String raw = ex.getCause() != null ? ex.getCause().getMessage() : null;
        if (raw != null && raw.startsWith("{") && raw.endsWith("}")) {
            raw = raw.substring(1, raw.length() - 1);
            for (String pair : raw.split(",")) {
                String[] kv = pair.split("=");
                if (kv.length == 2) {
                    errors.put(kv[0].trim(), kv[1].trim());
                }
            }
        } else if (ex.getReason() != null) {
            errors.put("error", ex.getReason());
        }
        ApiGenericResponse<Object> response = ApiGenericResponse.error(ex.getReason(), errors);
        return new ResponseEntity<>(response, ex.getStatusCode());
    }
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiGenericResponse<String>> handleIllegalArgumentException(IllegalArgumentException ex) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiGenericResponse.error(ex.getMessage()));
    }
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiGenericResponse<Object>> handleRuntimeException(RuntimeException ex) {
        ApiGenericResponse<Object> response = ApiGenericResponse.error(ex.getMessage());
        return ResponseEntity.badRequest().body(response);
    }

}
