package com.example.demo.service;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.example.demo.common.exception.UnauthorizedException;
import com.example.demo.common.exception.payload.ErrorCode;
import com.example.demo.infrastructure.jwks.JWKSProvider;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

@Service
public class JwtValidationService {

    private final JWKSProvider jwksProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtValidationService(JWKSProvider jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    public boolean validateToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new UnauthorizedException(ErrorCode.TOKEN_NOT_CORRECT_FORMAT);
            }

            String header = parts[0];
            String payload = parts[1];
            String signature = parts[2];

            String decodedHeader = new String(Base64.getUrlDecoder().decode(header), StandardCharsets.UTF_8);
            Map<String, String> headerMap = objectMapper.readValue(decodedHeader, new TypeReference<Map<String, String>>() {});
            String kid = headerMap.get("kid");

            Optional<String> publicKeyOpt = jwksProvider.getPublicKey(kid);
            if (publicKeyOpt.isEmpty()) {
                throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
            }

            String publicKey = publicKeyOpt.get();

            String dataToSign = header + "." + payload;
            if (!verifySignature(dataToSign, signature, publicKey)) {
                throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
            }

            String decodedPayload = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
            Map<String, Object> payloadMap = objectMapper.readValue(decodedPayload, new TypeReference<Map<String, Object>>() {});

            if (payloadMap.containsKey("exp")) {
                long exp = ((Number) payloadMap.get("exp")).longValue();
                if (Instant.now().getEpochSecond() > exp) {
                    throw new UnauthorizedException(ErrorCode.TOKEN_EXPIRATION);
                }
            } else {
                throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
            }

            return true;
        } catch (Exception e) {
            throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
        }
    }

    private boolean verifySignature(String data, String signature, String publicKey) {
        try {
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signature);
            byte[] keyBytes = Base64.getUrlDecoder().decode(publicKey);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(rsaPublicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }
}