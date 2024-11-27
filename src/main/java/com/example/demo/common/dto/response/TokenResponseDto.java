package com.example.demo.common.dto.response;

public record TokenResponseDto (String accessToknen,
								String idToken,
								String refreshToken) {

}