package com.killer.password_validator.controller;

import com.killer.password_validator.dto.PasswordEvaluationRequest;
import com.killer.password_validator.dto.PasswordEvaluationResponse;
import com.killer.password_validator.service.PasswordEvaluationService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/v1/password")
public class PasswordEvaluationController {

    private final PasswordEvaluationService evaluationService;

    public PasswordEvaluationController(PasswordEvaluationService evaluationService) {
        this.evaluationService = evaluationService;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<PasswordEvaluationResponse> evaluatePassword(
            @Valid @RequestBody PasswordEvaluationRequest request) {
        PasswordEvaluationResponse response = evaluationService.evaluatePassword(request);
        return ResponseEntity.ok(response);
    }
}
