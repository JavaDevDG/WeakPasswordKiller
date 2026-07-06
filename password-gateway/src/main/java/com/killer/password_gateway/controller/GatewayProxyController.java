package com.killer.password_gateway.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;

@Slf4j
@RestController
@RequestMapping("/api/v1/password")
public class GatewayProxyController {

    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, Bucket> cache = new ConcurrentHashMap<>();
    
    @Value("${validator.url:http://localhost:8081/api/v1/password/evaluate}")
    private String validatorUrl;

    public Bucket resolveBucket(String ip) {
        return cache.computeIfAbsent(ip, this::newBucket);
    }

    private Bucket newBucket(String ip) {
        // Limit: 10 requests per minute per IP
        Bandwidth limit = Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    @PostMapping("/evaluate")
    public ResponseEntity<?> proxyEvaluate(@RequestBody Object request, HttpServletRequest httpRequest) {
        String ip = httpRequest.getRemoteAddr();
        Bucket bucket = resolveBucket(ip);
        
        if (!bucket.tryConsume(1)) {
            log.warn("Rate limit exceeded for IP: {}", ip);
            return ResponseEntity.status(429).body("{\"error\": \"Too many requests. Please try again later.\"}");
        }
        
        log.info("Gateway received password evaluation request, routing to validator...");
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("Content-Type", "application/json");
            
            HttpEntity<Object> entity = new HttpEntity<>(request, headers);
            
            return restTemplate.exchange(
                    validatorUrl,
                    HttpMethod.POST,
                    entity,
                    Object.class
            );
        } catch (HttpClientErrorException | HttpServerErrorException e) {
            // Propagate the validator's status and JSON body (e.g. validation errors). We must NOT
            // copy the upstream headers verbatim: a stale Content-Length / Transfer-Encoding causes
            // the body to be dropped. Set a clean Content-Type instead.
            return ResponseEntity
                    .status(e.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Gateway failed to reach validator", e);
            return ResponseEntity.internalServerError().body("{\"error\": \"Internal Gateway Error\"}");
        }
    }
}
