package com.businesssystemssecurity.proj.exception;

public class EntityDoesNotBelongToException extends RuntimeException {
    public EntityDoesNotBelongToException(String message){
        super(message);
    }
}
