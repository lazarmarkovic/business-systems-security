package com.businesssystemssecurity.proj.exception;

public final class BadTokenException extends RuntimeException {

    public BadTokenException() {
        super("Bad token.");
    }

    public BadTokenException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public BadTokenException(final String message) {
        super(message);
    }

    public BadTokenException(final Throwable cause) {
        super(cause);
    }

}