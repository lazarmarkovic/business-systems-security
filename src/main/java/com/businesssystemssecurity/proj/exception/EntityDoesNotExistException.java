package com.businesssystemssecurity.proj.exception;

public class EntityDoesNotExistException extends RuntimeException {
    public EntityDoesNotExistException(String message){
        super(message);
    }
}
