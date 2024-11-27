package com.example.demo;

import com.example.demo.common.dto.response.TokenResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class TokenResponseDtoTest {

    @Test
    void testSerializationDeserialization() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.findAndRegisterModules(); // 필요한 모듈 등록

        // 원본 데이터
        TokenResponseDto original = new TokenResponseDto("access123", "id123", "refresh123");

        // 직렬화
        String json = objectMapper.writeValueAsString(original);
        System.out.println("Serialized JSON: " + json);

        // 역직렬화
        TokenResponseDto deserialized = objectMapper.readValue(json, TokenResponseDto.class);

        // 확인
        assertEquals(original, deserialized);
    }
}
