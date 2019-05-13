package com.businesssystemssecurity.proj.exception;


public class PKIMalfunctionException  extends RuntimeException {

    public PKIMalfunctionException() {
        super("Malfunction in PKI system.");
    }

    public PKIMalfunctionException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public PKIMalfunctionException(final String message) {
        super(message);
    }

    public PKIMalfunctionException(final Throwable cause) {
        super(cause);
    }

}