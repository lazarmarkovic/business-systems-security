package com.businesssystemssecurity.proj.security.conf;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import com.businesssystemssecurity.proj.handler.ApiError;
import com.businesssystemssecurity.proj.security.service.UserDetailsServiceImpl;
import com.businesssystemssecurity.proj.service.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

public class AuthenticationTokenFilter extends UsernamePasswordAuthenticationFilter {

    @Value("${jwt.token.header}")
    private String jwtHeader;

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private UserService userService;


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
        HttpServletRequest httpRequest = (HttpServletRequest) request;

        String authToken = httpRequest.getHeader(jwtHeader);

        try {
            if (authToken != null) {
                String email = this.tokenUtils.getEmailFromToken(authToken);
                userService.findByEmail(email);
                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            chain.doFilter(request, response);
        } catch (Exception ex) {
            HttpServletResponse hsr = (HttpServletResponse)response;
            hsr.setStatus(HttpStatus.BAD_REQUEST.value());
            ApiError apiError = new ApiError(BAD_REQUEST);
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
    }

}