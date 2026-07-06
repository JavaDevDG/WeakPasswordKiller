package com.killer.password_validator.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

import java.util.Set;

@Data
@Builder
public class PasswordEvaluationResponse {
    private int score;
    private PasswordStrength strength;
    private String warning;
    private List<String> suggestions;
    private Set<RuleViolation> violations;
    private boolean compromised;
    private String suggestedStrongPassword;
    private String crackTime;
    // "CHECKED" or "UNAVAILABLE" — was the breach lookup actually able to run (see HibpClient.BreachStatus).
    private String breachCheckStatus;
}
