package com.businesssystemssecurity.proj.exception;

public final class AccessDeniedException extends RuntimeException {

    public AccessDeniedException () {
        super("Access denied.");
    }

    public AccessDeniedException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public AccessDeniedException(final String message) {
        super(message);
    }

    public AccessDeniedException(final Throwable cause) {
        super(cause);
    }

}