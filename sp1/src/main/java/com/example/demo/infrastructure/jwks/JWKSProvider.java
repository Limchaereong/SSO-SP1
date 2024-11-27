package com.example.demo.infrastructure.jwks;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.example.demo.common.exception.NotFoundException;
import com.example.demo.common.exception.payload.ErrorCode;

@Component
public class JWKSProvider {

    private final String jwksUrl = "http://10.120.60.208:8080/jwks/jwks.json";
    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, String> publicKeys = new HashMap<>();

    public JWKSProvider() {
        loadPublicKeysFromJWKS();
    }

    private void loadPublicKeysFromJWKS() {
        try {
            Map<String, Object> response = restTemplate.getForObject(jwksUrl, Map.class);
            if (response != null && response.containsKey("keys")) {
                for (Map<String, Object> key : (Iterable<Map<String, Object>>) response.get("keys")) {
                    String kid = (String) key.get("kid");
                    String publicKey = (String) key.get("n");
                    publicKeys.put(kid, publicKey);
                }
            } else {
                throw new NotFoundException(ErrorCode.NOT_FOUND_KEYS);
            }
        } catch (Exception e) {
            System.err.println("JWKS 로드 실패: " + e.getMessage());
        }
    }

    public Optional<String> getPublicKey(String kid) {
        return Optional.ofNullable(publicKeys.get(kid));
    }
}