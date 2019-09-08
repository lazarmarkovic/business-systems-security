package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.*;
import com.businesssystemssecurity.proj.exception.AccessDeniedException;
import com.businesssystemssecurity.proj.exception.BadRegistrationParametersException;
import com.businesssystemssecurity.proj.exception.EntityNotFoundException;
import com.businesssystemssecurity.proj.repository.PermissionRepository;
import com.businesssystemssecurity.proj.repository.UserRepository;
import com.businesssystemssecurity.proj.repository.connectors.UserAuthorityRepository;
import com.businesssystemssecurity.proj.repository.connectors.UserPermissionRepository;
import com.businesssystemssecurity.proj.security.service.AuthService;
import com.businesssystemssecurity.proj.web.dto.user.UserPasswordDTO;
import com.businesssystemssecurity.proj.web.dto.user.UserRegistrationDTO;
import com.businesssystemssecurity.proj.web.dto.user.UserUpdateDTO;
import com.businesssystemssecurity.proj.web.dto.user.UserUpdatePermissionsDTO;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {


    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthService authService;

    @Autowired
    private PermissionService permissionService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthorityService authorityService;

    @Autowired
    private UserAuthorityRepository userAuthorityRepository;

    @Autowired
    private UserPermissionRepository userPermissionRepository;



    @Override
    public User findById(long id) {
        Optional<User> opt = this.userRepository.findById(id);
        return opt.orElseThrow(() -> new EntityNotFoundException(User.class, "id", Long.toString(id)));
    }

    @Override
    public User findByEmail(String email) {
        Optional<User> opt = this.userRepository.findByEmail(email);
        return opt.orElseThrow(() -> new EntityNotFoundException(User.class, "email", email));
    }

    @Override
    public User getUserById(long id) {
        User authUser = authService.getAuthUser();

        if (authUser.getId() != id) {
            throw new AccessDeniedException();
        }

        return authUser;
    }

    @Override
    public ArrayList<User> findAll() {
        return (ArrayList<User>)userRepository.findAll();
    }


    @Override
    @Transactional
    public User create(UserRegistrationDTO userRegistrationDTO) {
        Optional<User> user = userRepository.findByEmail(userRegistrationDTO.getEmail());
        if (user.isPresent()) {
            throw new BadRegistrationParametersException("User with given email is already registered.");
        }

        User newUser = new User();
        newUser.setFirstName(userRegistrationDTO.getFirstName());
        newUser.setLastName(userRegistrationDTO.getLastName());
        newUser.setEmail(userRegistrationDTO.getEmail());
        newUser.setPassword(passwordEncoder.encode(userRegistrationDTO.getPassword()));
        User createdUser = userRepository.save(newUser);


        Authority authority = authorityService.findById(userRegistrationDTO.getAuthorityId());
        UserAuthority ua = new UserAuthority();
        ua.setAuthority(authority);
        ua.setUser(createdUser);
        this.userAuthorityRepository.save(ua);

        for (long permissionId : userRegistrationDTO.getPermissions()) {
            Permission p = this.permissionService.findById(permissionId);
            UserPermission up = new UserPermission();
            up.setPermission(p);
            up.setUser(createdUser);
            this.userPermissionRepository.save(up);
        }

        return createdUser;
    }

    @Override
    @Transactional
    public User update(long userId, UserUpdateDTO userUpdateDTO) {
        User authUser = authService.getAuthUser();

        if (authUser.getId() != userId) {
            throw new AccessDeniedException();
        }

        User updateUser = findById(userId);
        updateUser.setFirstName(userUpdateDTO.getFirstName());
        updateUser.setLastName(userUpdateDTO.getLastName());

        return userRepository.save(updateUser);
    }

    @Override
    @Transactional
    public User updatePermissions(long userId, UserUpdatePermissionsDTO userUpdatePermissionsDTO) {
        try{
        System.out.println(userUpdatePermissionsDTO);

        User updateUser = findById(userId);
        updateUser.setSuspended(userUpdatePermissionsDTO.isSuspended());
        userRepository.save(updateUser);

//        System.out.println("Deleting");
//        this.userPermissionRepository.deleteUserPermissionsByUserId(userId);
//        System.out.println("Finish deleting");


        ArrayList<UserPermission> userPermissions = this.userPermissionRepository.findUserPermissionsByUserId(userId);

        for (UserPermission up : userPermissions) {
            System.out.println("Nasao sam ovo: " + up.getId());
            up.setUser(null);
            up.setPermission(null);
            this.userPermissionRepository.save(up);
            System.out.println("Postavio.");
        }

        ArrayList<Long> ids = (ArrayList<Long>)userPermissions
                .stream()
                .map((value) -> {
                    return value.getId();
                })
                .collect(Collectors.toList());

        for (Long id : ids) {
            this.userPermissionRepository.deleteById(id);
            System.out.println("Isbrisao");
        }

        for (long permissionId : userUpdatePermissionsDTO.getPermissions()) {
            Permission p = this.permissionService.findById(permissionId);
            UserPermission up = new UserPermission();
            up.setPermission(p);
            up.setUser(updateUser);
            this.userPermissionRepository.save(up);

        }
            return updateUser;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    @Transactional
    public User changePassword(long userId, UserPasswordDTO userPasswordDTO) {
        User authUser = authService.getAuthUser();
        if (authUser.getId() != userId) {
            throw new AccessDeniedException();
        }

        User updateUser = findById(userId);

        if (!passwordEncoder.matches(userPasswordDTO.getOldPassword(), updateUser.getPassword())) {
            throw new AccessDeniedException();
        }

        updateUser.setPassword(passwordEncoder.encode(userPasswordDTO.getNewPassword()));
        return userRepository.save(updateUser);
    }

    @Override
    @Transactional
    public void delete(long userId) {
        User authUser = authService.getAuthUser();
        if (authUser.getId() != userId) {
            throw new AccessDeniedException();
        }
        ArrayList<UserAuthority> userAuthorities = this.userAuthorityRepository.findUserAuthoritiesByUserId(userId);
        for (UserAuthority ua : userAuthorities) {
            this.userAuthorityRepository.delete(ua);
        }

        ArrayList<UserPermission> userPermissions = this.userPermissionRepository.findUserPermissionsByUserId(userId);
        for (UserPermission up : userPermissions) {
            this.userPermissionRepository.delete(up);
        }

        User user = this.findById(userId);
        this.userRepository.delete(user);

    }
}
