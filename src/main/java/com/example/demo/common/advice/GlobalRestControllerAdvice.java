package com.example.demo.common.advice;

import com.example.demo.common.exception.BadRequestException;
import com.example.demo.common.exception.ConflictException;
import com.example.demo.common.exception.InternalServerErrorException;
import com.example.demo.common.exception.NotFoundException;
import com.example.demo.common.exception.UnauthorizedException;
import com.example.demo.common.response.ApiResponse;
import com.example.demo.common.response.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalRestControllerAdvice {

	@ExceptionHandler(BadRequestException.class)
	public ResponseEntity<ApiResponse<ErrorResponse>> handleBadRequestException(BadRequestException e) {
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode());
		return ResponseEntity
			.status(e.getErrorCode().getHttpStatus())
			.body(ApiResponse.error(errorResponse));
	}

	@ExceptionHandler(UnauthorizedException.class)
	public ResponseEntity<ApiResponse<ErrorResponse>> handleUnauthorizedException(UnauthorizedException e) {
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode());
		return ResponseEntity
			.status(e.getErrorCode().getHttpStatus())
			.body(ApiResponse.error(errorResponse));
	}

	@ExceptionHandler(InternalServerErrorException.class)
	public ResponseEntity<ApiResponse<ErrorResponse>> handleInternalServerErrorException(
		InternalServerErrorException e) {
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode());
		return ResponseEntity
			.status(e.getErrorCode().getHttpStatus())
			.body(ApiResponse.error(errorResponse));
	}

	@ExceptionHandler(ConflictException.class)
	public ResponseEntity<ApiResponse<ErrorResponse>> handleConflictException(
		ConflictException e) {
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode());
		return ResponseEntity
			.status(e.getErrorCode().getHttpStatus())
			.body(ApiResponse.error(errorResponse));
	}

	@ExceptionHandler(NotFoundException.class)
	public ResponseEntity<ApiResponse<ErrorResponse>> handleNotFoundException(
		NotFoundException e) {
		ErrorResponse errorResponse = ErrorResponse.of(e.getErrorCode());
		return ResponseEntity
			.status(e.getErrorCode().getHttpStatus())
			.body(ApiResponse.error(errorResponse));
	}
}