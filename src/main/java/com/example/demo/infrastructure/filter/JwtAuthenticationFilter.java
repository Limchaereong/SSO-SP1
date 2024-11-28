package com.example.demo.infrastructure.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import com.example.demo.common.exception.UnauthorizedException;
import com.example.demo.common.exception.payload.ErrorCode;
import com.example.demo.common.response.ApiResponse;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();
    private String publicKeyValue;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String token = getTokenFromCookie(request);

        if (token == null) {
            response.sendRedirect("http://10.120.60.208:8080/loginForm");
            return;
        }

        String spIdentifier = getSpIdentifier();
        request.setAttribute("SP-Identifier", spIdentifier);

        try {
            fetchPublicKeyFromIdp();
            boolean isValid = verifyToken(token);
            if (!isValid) {
                throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
            }

            String newIdToken = requestNewIdToken(spIdentifier, token);
            Cookie idTokenCookie = new Cookie("idToken", newIdToken);
            idTokenCookie.setHttpOnly(true);
            idTokenCookie.setPath("/");
            response.addCookie(idTokenCookie);
        } catch (Exception e) {
            response.sendRedirect("http://10.120.60.208:8080/loginForm");
            return;
        }

        chain.doFilter(request, response);
    }

    private void fetchPublicKeyFromIdp() {
        String url = "http://10.120.60.208:8080/api/publicKey";
        try {
            publicKeyValue = restTemplate.getForObject(url, String.class);
            if (publicKeyValue == null || publicKeyValue.isEmpty()) {
                throw new RuntimeException("Public key fetch failed");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch public key from IDP server", e);
        }
    }

    private boolean verifyToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT format");
            }

            String headerAndPayload = parts[0] + "." + parts[1];
            String signature = parts[2];

            return verifySignature(headerAndPayload, signature);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean verifySignature(String data, String signature) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKeyValue);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(publicKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));

            return sig.verify(Base64.getUrlDecoder().decode(signature));
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private String requestNewIdToken(String spIdentifier, String accessToken) {
        String url = "http://10.120.60.208:8080/token/generateIdToken";

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("accessToken", accessToken);
            headers.set("SP-Identifier", spIdentifier);

            HttpEntity<String> requestEntity = new HttpEntity<>(headers);

            ResponseEntity<String> responseEntity = restTemplate.postForEntity(url, requestEntity, String.class);

            if (!responseEntity.getStatusCode().is2xxSuccessful()) {
                throw new UnauthorizedException(ErrorCode.TOKEN_GENERATION_FAILED);
            }

            String responseBody = responseEntity.getBody();
            ApiResponse<String> apiResponse = objectMapper.readValue(responseBody, new TypeReference<ApiResponse<String>>() {});

            if (apiResponse.getData() != null) {
                return apiResponse.getData();
            } else {
                throw new UnauthorizedException(ErrorCode.TOKEN_GENERATION_FAILED);
            }

        } catch (Exception e) {
            e.printStackTrace();
            throw new UnauthorizedException(ErrorCode.TOKEN_GENERATION_FAILED);
        }
    }

    private String getSpIdentifier() {
        return "SP1";
    }

    public String getTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
