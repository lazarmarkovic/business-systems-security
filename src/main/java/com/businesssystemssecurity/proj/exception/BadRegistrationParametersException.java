package com.businesssystemssecurity.proj.exception;

public class BadRegistrationParametersException  extends RuntimeException {

    public BadRegistrationParametersException() {
        super("Bad registration parameters.");
    }

    public BadRegistrationParametersException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public BadRegistrationParametersException(final String message) {
        super(message);
    }

    public BadRegistrationParametersException(final Throwable cause) {
        super(cause);
    }

}