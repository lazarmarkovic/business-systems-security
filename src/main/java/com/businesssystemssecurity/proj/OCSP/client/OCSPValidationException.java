package com.businesssystemssecurity.proj.OCSP.client;

/**
 *
 * @author POReID
 */
public class OCSPValidationException extends Exception{

    public OCSPValidationException(String msg, Throwable cause){
        super(msg, cause);
    }

    public OCSPValidationException(String msg) {
        super(msg);
    }

}