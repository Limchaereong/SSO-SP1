package com.example.demo.common.exception;

import com.example.demo.common.exception.payload.ErrorCode;

import lombok.Getter;

// 500 - Internal Server Error
@Getter
public class InternalServerErrorException extends RuntimeException {
	private final ErrorCode errorCode;

	public InternalServerErrorException(ErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}
	
	public ErrorCode getErrorCode() {
        return errorCode;
    }
	
}