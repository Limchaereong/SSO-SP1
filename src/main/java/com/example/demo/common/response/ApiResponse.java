package com.example.demo.common.response;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ApiResponse<T> {

    private final boolean success;
    private final T data;
    private final ErrorResponse error;

    @JsonCreator
    public ApiResponse(@JsonProperty("success") boolean success,
                       @JsonProperty("data") T data,
                       @JsonProperty("error") ErrorResponse error) {
        this.success = success;
        this.data = data;
        this.error = error;
    }

    // 성공 응답
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, data, null);
    }

    // 실패 응답
    public static <T> ApiResponse<T> error(ErrorResponse error) {
        return new ApiResponse<>(false, null, error);
    }

    public boolean isSuccess() {
        return success;
    }

    public T getData() {
        return data;
    }

    public ErrorResponse getError() {
        return error;
    }
}