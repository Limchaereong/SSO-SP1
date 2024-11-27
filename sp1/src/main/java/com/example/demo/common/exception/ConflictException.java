package com.example.demo.common.exception;

import com.example.demo.common.exception.payload.ErrorCode;

import lombok.Getter;

//409
@Getter
public class ConflictException extends RuntimeException {
	private final ErrorCode errorCode;

	public ConflictException(ErrorCode errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}
	
	public ErrorCode getErrorCode() {
        return errorCode;
    }
	
}