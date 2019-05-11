package com.businesssystemssecurity.proj.security.web.controller;

import com.businesssystemssecurity.proj.security.service.AuthService;
import com.businesssystemssecurity.proj.security.web.dto.LoginDTO;
import com.businesssystemssecurity.proj.security.web.dto.LoginResponseDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;


    @RequestMapping(value = "/login",
            method = RequestMethod.POST,
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginResponseDTO> login(@RequestBody @Valid LoginDTO loginDTO) {
        String token = authService.authenticate(loginDTO.getEmail(), loginDTO.getPassword());

        Long userId = authService.getAuthUser().getId();
        return new ResponseEntity<>(new LoginResponseDTO(userId, token), HttpStatus.OK);
    }


}