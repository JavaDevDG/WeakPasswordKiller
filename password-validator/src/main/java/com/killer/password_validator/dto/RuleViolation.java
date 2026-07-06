package com.killer.password_validator.dto;

public enum RuleViolation {
    TOO_SHORT,
    COMPROMISED,
    CONTAINS_PERSONAL_INFO,
    EASILY_GUESSABLE,
    LACKS_COMPLEXITY
}
