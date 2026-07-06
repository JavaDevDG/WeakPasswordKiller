package com.killer.password_validator.service;

import com.killer.password_validator.client.HibpClient;
import com.killer.password_validator.dto.PasswordEvaluationRequest;
import com.killer.password_validator.dto.PasswordEvaluationResponse;
import com.killer.password_validator.dto.PasswordStrength;
import com.killer.password_validator.dto.RuleViolation;
import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Counter;

@Slf4j
@Service
public class PasswordEvaluationService {

    private final Zxcvbn zxcvbn;
    private final HibpClient hibpClient;
    private final StrongPasswordGenerator passwordGenerator;
    private final Counter weakPasswordCounter;
    private final Counter strongPasswordCounter;
    private final Counter compromisedPasswordCounter;

    public PasswordEvaluationService(HibpClient hibpClient, StrongPasswordGenerator passwordGenerator, MeterRegistry meterRegistry) {
        this.zxcvbn = new Zxcvbn();
        this.hibpClient = hibpClient;
        this.passwordGenerator = passwordGenerator;
        this.weakPasswordCounter = meterRegistry.counter("passwords.evaluated", "result", "weak");
        this.strongPasswordCounter = meterRegistry.counter("passwords.evaluated", "result", "strong");
        this.compromisedPasswordCounter = meterRegistry.counter("passwords.evaluated", "result", "compromised");
    }

    public PasswordEvaluationResponse evaluatePassword(PasswordEvaluationRequest request) {
        log.info("Evaluating password for user: {}", request.getUsername());
        
        List<String> sanitizedInputs = new ArrayList<>();
        if (request.getUsername() != null) sanitizedInputs.add(request.getUsername());
        if (request.getEmail() != null) sanitizedInputs.add(request.getEmail());

        Strength strength = zxcvbn.measure(request.getPassword(), sanitizedInputs);

        HibpClient.BreachCheckResult breachResult = hibpClient.isPasswordCompromised(request.getPassword());
        boolean isCompromised = breachResult.compromised();

        Set<RuleViolation> violations = new HashSet<>();
        if (isCompromised) {
            violations.add(RuleViolation.COMPROMISED);
            compromisedPasswordCounter.increment();
        }
        if (request.getPassword().length() < 8) {
            violations.add(RuleViolation.TOO_SHORT);
        }
        if (strength.getScore() < 2) {
            violations.add(RuleViolation.EASILY_GUESSABLE);
        }
        if (containsPersonalInfo(request)) {
            violations.add(RuleViolation.CONTAINS_PERSONAL_INFO);
        }

        int finalScore = strength.getScore();
        if (isCompromised) {
            finalScore = 0;
        }

        PasswordStrength enumStrength = mapScoreToStrength(finalScore);

        String warning = strength.getFeedback().getWarning();
        if (isCompromised) {
            warning = "This password has appeared in a data breach. You must not use it!";
        }

        PasswordEvaluationResponse.PasswordEvaluationResponseBuilder responseBuilder = PasswordEvaluationResponse.builder()
                .score(finalScore)
                .strength(enumStrength)
                .warning(warning)
                .suggestions(strength.getFeedback().getSuggestions())
                .violations(violations)
                .compromised(isCompromised)
                .crackTime(strength.getCrackTimesDisplay().getOfflineFastHashing1e10PerSecond())
                .breachCheckStatus(breachResult.status().name());

        if (finalScore < 3) {
            weakPasswordCounter.increment();
            String suggestion = passwordGenerator.generateStrongPassword();
            responseBuilder.suggestedStrongPassword(suggestion);
            log.info("Password was weak. Generated a strong suggestion for user: {}", request.getUsername());
        } else {
            strongPasswordCounter.increment();
            log.info("Password evaluated as STRONG for user: {}", request.getUsername());
        }

        return responseBuilder.build();
    }

    /**
     * Flags the password if it contains the user's username or email (full address or the
     * local part before '@'). Comparison is case-insensitive. Empty inputs are ignored so a
     * blank username/email never triggers a false positive.
     */
    private boolean containsPersonalInfo(PasswordEvaluationRequest request) {
        String password = request.getPassword().toLowerCase();

        String username = request.getUsername();
        if (username != null && !username.isBlank() && password.contains(username.toLowerCase())) {
            return true;
        }

        String email = request.getEmail();
        if (email != null && !email.isBlank()) {
            String lowerEmail = email.toLowerCase();
            if (password.contains(lowerEmail)) {
                return true;
            }
            String localPart = lowerEmail.split("@")[0];
            if (localPart.length() >= 3 && password.contains(localPart)) {
                return true;
            }
        }

        return false;
    }

    private PasswordStrength mapScoreToStrength(int score) {
        return switch (score) {
            case 0 -> PasswordStrength.VERY_WEAK;
            case 1 -> PasswordStrength.WEAK;
            case 2 -> PasswordStrength.FAIR;
            case 3 -> PasswordStrength.GOOD;
            case 4 -> PasswordStrength.STRONG;
            default -> PasswordStrength.VERY_WEAK;
        };
    }
}
