package com.businesssystemssecurity.proj.web.controller;

import com.businesssystemssecurity.proj.domain.User;
import com.businesssystemssecurity.proj.exception.AccessDeniedException;
import com.businesssystemssecurity.proj.security.service.AuthService;
import com.businesssystemssecurity.proj.seeder.data.PermissionTableSeed;
import com.businesssystemssecurity.proj.service.UserService;
import com.businesssystemssecurity.proj.web.dto.user.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private AuthService authService;


    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    @RequestMapping(value = "/{id}",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDTO> getUserById(@PathVariable Long id) {

        User user = userService.getUserById(id);
        return new ResponseEntity<>(new UserDTO(user), HttpStatus.OK);
    }

    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    @RequestMapping(value = "",
            method = RequestMethod.GET,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ArrayList<UserDTO>> getAll() {
        if (!this.authService.hasPermission(PermissionTableSeed.EDIT_USER_PERMISSIONS)) {
            throw new AccessDeniedException("User has no permission to list all users.");
        }
        this.authService.hasPermission(PermissionTableSeed.EDIT_USER_PERMISSIONS);
        ArrayList<User> users = this.userService.findAll();
        ArrayList <UserDTO> userDTOS = (ArrayList<UserDTO>) users
                .stream()
                .map(UserDTO::new)
                .collect(Collectors.toList());

        return new ResponseEntity<>(userDTOS, HttpStatus.OK);
    }

    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    @RequestMapping(value = "",
            method = RequestMethod.POST,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDTO> create(@RequestBody @Valid UserRegistrationDTO userRegistrationDTO) {
        if (!this.authService.hasPermission(PermissionTableSeed.REGISTER_USERS)) {
            throw new AccessDeniedException("User has no permission to register new user.");
        }
        // Not good way to sort this out..
        Long AUTHORITY_ID = 2L;
        userRegistrationDTO.setAuthorityId(AUTHORITY_ID);

        User user = userService.create(userRegistrationDTO);
        return new ResponseEntity<>(new UserDTO(user), HttpStatus.CREATED);
    }

    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    @RequestMapping(value = "/{id}",
            method = RequestMethod.PUT,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDTO> update(@PathVariable Long id, @RequestBody @Valid UserUpdateDTO userUpdateDTO) {
        User user = userService.update(id, userUpdateDTO);
        return new ResponseEntity<>(new UserDTO(user), HttpStatus.OK);
    }

    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    @RequestMapping(value = "/{id}/permissions",
            method = RequestMethod.PUT,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDTO> updatePermissions(@PathVariable Long id, @RequestBody @Valid UserUpdatePermissionsDTO userUpdatePermissionsDTO) {
        if (!this.authService.hasPermission(PermissionTableSeed.EDIT_USER_PERMISSIONS)) {
            throw new AccessDeniedException("User has no permission to edit user.");
        }
        User user = userService.updatePermissions(id, userUpdatePermissionsDTO);
        return new ResponseEntity<>(new UserDTO(user), HttpStatus.OK);
    }

    @PreAuthorize("hasAnyAuthority('admin', 'regular')")
    @RequestMapping(value = "/{id}/password",
            method = RequestMethod.PUT,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<UserDTO> changePassword(@PathVariable Long id, @RequestBody @Valid UserPasswordDTO userPasswordDTO) {
        User user = userService.changePassword(id, userPasswordDTO);
        return new ResponseEntity<>(new UserDTO(user), HttpStatus.OK);
    }

}
