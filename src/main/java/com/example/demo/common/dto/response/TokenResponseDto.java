package com.example.demo.common.dto.response;

public record TokenResponseDto (String accessToken,
								String idToken,
								String refreshToken) {

}