package com.businesssystemssecurity.proj.security.conf;

import com.businesssystemssecurity.proj.handler.ApiError;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@Component
public class CustomBasicAuthenticationEntryPoint extends BasicAuthenticationEntryPoint {

    @Override
    public void commence
            (HttpServletRequest request, HttpServletResponse response, AuthenticationException ex)
            throws IOException, ServletException {

        HttpServletResponse hsr = (HttpServletResponse)response;
        hsr.setStatus(HttpStatus.FORBIDDEN.value());
        ApiError apiError = new ApiError(FORBIDDEN);
        apiError.setMessage(ex.getMessage());

        ObjectMapper om = new ObjectMapper();
        om.registerModule(new JavaTimeModule());
        om.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        try {
            String json = om.writeValueAsString(apiError);

            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write(json);
            response.flushBuffer();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        setRealmName("Error");
        super.afterPropertiesSet();
    }
}
