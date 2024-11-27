package com.example.demo.common.exception;

import com.example.demo.common.exception.payload.ErrorCode;

import lombok.Getter;

// 400 - Bad Request
@Getter
public class BadRequestException extends RuntimeException {
	private final ErrorCode errorCode;

	public BadRequestException(ErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}
	
	public ErrorCode getErrorCode() {
        return errorCode;
    }
	
}