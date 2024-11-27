package com.example.demo.common.response;

import java.time.LocalDateTime;
import com.example.demo.common.exception.payload.ErrorCode;

public class ErrorResponse {

    private final String message;
    private final int status;
    private final LocalDateTime timestamp;

    // 생성자
    public ErrorResponse(String message, int status, LocalDateTime timestamp) {
        this.message = message;
        this.status = status;
        this.timestamp = timestamp;
    }

    public static ErrorResponse of(ErrorCode errorCode) {
        return new ErrorResponse(
                errorCode.getMessage(),
                errorCode.getHttpStatus().value(),
                LocalDateTime.now()
        );
    }

    public String getMessage() {
        return message;
    }

    public int getStatus() {
        return status;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }
}