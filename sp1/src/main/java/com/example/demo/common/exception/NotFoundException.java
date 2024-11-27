package com.example.demo.common.exception;

import com.example.demo.common.exception.payload.ErrorCode;

import lombok.Getter;

// 404 - Bad Request
@Getter
public class NotFoundException extends RuntimeException {
	private final ErrorCode errorCode;

	public NotFoundException(ErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}
	
	public ErrorCode getErrorCode() {
        return errorCode;
    }
	
}