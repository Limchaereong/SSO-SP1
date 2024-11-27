package com.example.demo.infrastructure.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

import com.example.demo.common.exception.UnauthorizedException;
import com.example.demo.common.exception.payload.ErrorCode;
import com.example.demo.common.response.ApiResponse;
import com.example.demo.infrastructure.jwks.JWKSProvider;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JWKSProvider jwksProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();

    public JwtAuthenticationFilter(JWKSProvider jwksProvider) {
        this.jwksProvider = jwksProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String token = getTokenFromCookie(request);

        if (token == null) {
            response.sendRedirect("http://10.120.60.208:8080/loginForm");
            return;
        }

//        Optional<String> userIdOpt = validateAndExtractUserId(token);
//
//        if (userIdOpt.isEmpty()) {
//            response.sendRedirect("http://10.120.60.208:8080/loginForm");
//            return;
//        }

        String spIdentifier = getSpIdentifier();
        request.setAttribute("SP-Identifier", spIdentifier);

        try {
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
            ObjectMapper objectMapper = new ObjectMapper();

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

//    public Optional<String> validateAndExtractUserId(String token) {
//        try {
//            String[] parts = token.split("\\.");
//            if (parts.length != 3) {
//                throw new UnauthorizedException(ErrorCode.TOKEN_NOT_CORRECT_FORMAT);
//            }
//
//            String header = parts[0];
//            String payload = parts[1];
//            // String signature = parts[2];
//
//            String decodedHeader = new String(Base64.getUrlDecoder().decode(header), StandardCharsets.UTF_8);
//            Map<String, String> headerMap = objectMapper.readValue(decodedHeader, new TypeReference<Map<String, String>>() {});
//            String kid = headerMap.get("kid");
//
//            Optional<String> publicKeyOpt = jwksProvider.getPublicKey(kid);
//            if (publicKeyOpt.isEmpty()) {
//                throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
//            }
//
//            String decodedPayload = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
//            Map<String, Object> payloadMap = objectMapper.readValue(decodedPayload, new TypeReference<Map<String, Object>>() {});
//
//            if (payloadMap.containsKey("expiration")) {
//                long expiration = Long.parseLong(payloadMap.get("expiration").toString());
//                if (Instant.now().toEpochMilli() > expiration) {
//                    throw new UnauthorizedException(ErrorCode.TOKEN_EXPIRATION);
//                }
//            } else {
//                throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
//            }
//
//            return Optional.ofNullable((String) payloadMap.get("userId"));
//
//        } catch (Exception e) {
//            throw new UnauthorizedException(ErrorCode.TOKEN_VALIDATION_FAILED);
//        }
//    }
}