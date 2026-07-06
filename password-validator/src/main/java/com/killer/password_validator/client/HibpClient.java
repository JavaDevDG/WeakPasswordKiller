package com.killer.password_validator.client;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

@Component
public class HibpClient {

    /** Whether the breach lookup actually ran against HIBP. */
    public enum BreachStatus {
        /** Password was compared against the HIBP dataset. */
        CHECKED,
        /** HIBP could not be reached; breach status is unknown. */
        UNAVAILABLE
    }

    /**
     * Outcome of a breach lookup. We fail <b>open</b> (an HIBP outage must not block the user)
     * but never <b>silently</b>: {@code status == UNAVAILABLE} tells the caller that
     * {@code compromised == false} is unverified rather than confirmed.
     */
    public record BreachCheckResult(boolean compromised, BreachStatus status) {
    }

    private static final String HIBP_API_URL = "https://api.pwnedpasswords.com/range/";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private final HttpClient httpClient;

    public HibpClient() {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .connectTimeout(CONNECT_TIMEOUT)
                .build();
    }

    public BreachCheckResult isPasswordCompromised(String password) {
        if (password == null || password.isEmpty()) {
            return new BreachCheckResult(false, BreachStatus.CHECKED);
        }

        String sha1Hash = getSha1Hex(password);
        String prefix = sha1Hash.substring(0, 5);
        String suffix = sha1Hash.substring(5);

        String responseBody = fetchHibpData(prefix);

        // Fail open, but transparently: if HIBP was unreachable we report UNAVAILABLE rather
        // than claiming the password is safe.
        if (responseBody == null) {
            return new BreachCheckResult(false, BreachStatus.UNAVAILABLE);
        }

        String[] lines = responseBody.split("\\r?\\n");
        for (String line : lines) {
            if (line.startsWith(suffix)) {
                return new BreachCheckResult(true, BreachStatus.CHECKED);
            }
        }

        return new BreachCheckResult(false, BreachStatus.CHECKED);
    }

    @Cacheable(value = "hibp-prefix", key = "#prefix")
    public String fetchHibpData(String prefix) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(HIBP_API_URL + prefix))
                    .header("User-Agent", "WeakPasswordKiller-Service")
                    .timeout(REQUEST_TIMEOUT)
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return response.body();
            }
        } catch (Exception e) {
            System.err.println("Failed to check HIBP API: " + e.getMessage());
        }
        return null;
    }

    private String getSha1Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02X", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not found", e);
        }
    }
}
