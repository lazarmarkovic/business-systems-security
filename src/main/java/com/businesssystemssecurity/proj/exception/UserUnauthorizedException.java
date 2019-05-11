package com.businesssystemssecurity.proj.exception;

public class UserUnauthorizedException  extends RuntimeException {

    public UserUnauthorizedException() {
        super("User unauthorized");
    }

    public UserUnauthorizedException(final String message, final Throwable cause) {
        super(message, cause);
    }

    public UserUnauthorizedException(final String message) {
        super(message);
    }

    public UserUnauthorizedException(final Throwable cause) {
        super(cause);
    }

}