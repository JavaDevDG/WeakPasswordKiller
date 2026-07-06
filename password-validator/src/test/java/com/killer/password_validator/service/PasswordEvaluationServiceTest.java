package com.killer.password_validator.service;

import com.killer.password_validator.client.HibpClient;
import com.killer.password_validator.dto.PasswordEvaluationRequest;
import com.killer.password_validator.dto.PasswordEvaluationResponse;
import com.killer.password_validator.dto.PasswordStrength;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordEvaluationServiceTest {

    @Mock
    private HibpClient hibpClient;

    @Mock
    private MeterRegistry meterRegistry;
    
    @Mock
    private Counter mockCounter;

    private PasswordEvaluationService service;
    private StrongPasswordGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new StrongPasswordGenerator();
        when(meterRegistry.counter(anyString(), anyString(), anyString())).thenReturn(mockCounter);
        service = new PasswordEvaluationService(hibpClient, generator, meterRegistry);
    }

    @Test
    void evaluatePassword_weakPassword() {
        when(hibpClient.isPasswordCompromised(anyString()))
                .thenReturn(new HibpClient.BreachCheckResult(false, HibpClient.BreachStatus.CHECKED));

        PasswordEvaluationRequest request = new PasswordEvaluationRequest();
        request.setPassword("password123");
        
        PasswordEvaluationResponse response = service.evaluatePassword(request);

        assertEquals(0, response.getScore());
        assertEquals(PasswordStrength.VERY_WEAK, response.getStrength());
        assertNotNull(response.getSuggestedStrongPassword());
        assertTrue(response.getViolations().contains(com.killer.password_validator.dto.RuleViolation.EASILY_GUESSABLE));
    }

    @Test
    void evaluatePassword_compromisedPassword() {
        when(hibpClient.isPasswordCompromised(anyString()))
                .thenReturn(new HibpClient.BreachCheckResult(true, HibpClient.BreachStatus.CHECKED));

        PasswordEvaluationRequest request = new PasswordEvaluationRequest();
        request.setPassword("CorrectHorseBatteryStaple123!");
        
        PasswordEvaluationResponse response = service.evaluatePassword(request);

        assertEquals(0, response.getScore());
        assertEquals(PasswordStrength.VERY_WEAK, response.getStrength());
        assertTrue(response.isCompromised());
        assertTrue(response.getWarning().contains("data breach"));
        assertNotNull(response.getSuggestedStrongPassword());
        assertTrue(response.getViolations().contains(com.killer.password_validator.dto.RuleViolation.COMPROMISED));
    }

    @Test
    void evaluatePassword_strongPassword() {
        when(hibpClient.isPasswordCompromised(anyString()))
                .thenReturn(new HibpClient.BreachCheckResult(false, HibpClient.BreachStatus.CHECKED));

        PasswordEvaluationRequest request = new PasswordEvaluationRequest();
        request.setPassword("T$1pLq9*!aXb@8mP");
        
        PasswordEvaluationResponse response = service.evaluatePassword(request);

        assertTrue(response.getScore() >= 3);
        assertNull(response.getSuggestedStrongPassword());
        assertFalse(response.isCompromised());
    }

    @Test
    void evaluatePassword_containsUsername() {
        when(hibpClient.isPasswordCompromised(anyString()))
                .thenReturn(new HibpClient.BreachCheckResult(false, HibpClient.BreachStatus.CHECKED));

        PasswordEvaluationRequest request = new PasswordEvaluationRequest();
        request.setUsername("johndoe");
        request.setPassword("johndoe123!");
        
        PasswordEvaluationResponse response = service.evaluatePassword(request);

        assertTrue(response.getScore() <= 2);
        assertTrue(response.getViolations().contains(com.killer.password_validator.dto.RuleViolation.CONTAINS_PERSONAL_INFO));
    }

    @Test
    void evaluatePassword_containsEmailLocalPart() {
        when(hibpClient.isPasswordCompromised(anyString()))
                .thenReturn(new HibpClient.BreachCheckResult(false, HibpClient.BreachStatus.CHECKED));

        PasswordEvaluationRequest request = new PasswordEvaluationRequest();
        request.setEmail("okenobi@jedi-council.com");
        request.setPassword("Xokenobi99!Q");

        PasswordEvaluationResponse response = service.evaluatePassword(request);

        assertTrue(response.getViolations().contains(com.killer.password_validator.dto.RuleViolation.CONTAINS_PERSONAL_INFO));
    }

    @Test
    void evaluatePassword_breachCheckUnavailable_reportsUnavailable() {
        when(hibpClient.isPasswordCompromised(anyString()))
                .thenReturn(new HibpClient.BreachCheckResult(false, HibpClient.BreachStatus.UNAVAILABLE));

        PasswordEvaluationRequest request = new PasswordEvaluationRequest();
        request.setPassword("T$1pLq9*!aXb@8mP");

        PasswordEvaluationResponse response = service.evaluatePassword(request);

        assertEquals("UNAVAILABLE", response.getBreachCheckStatus());
        assertFalse(response.isCompromised());
    }
}
