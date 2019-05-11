package com.businesssystemssecurity.proj.service;


import com.businesssystemssecurity.proj.domain.User;
import com.businesssystemssecurity.proj.web.dto.user.UserPasswordDTO;
import com.businesssystemssecurity.proj.web.dto.user.UserRegistrationDTO;
import com.businesssystemssecurity.proj.web.dto.user.UserUpdateDTO;

import java.util.ArrayList;


public interface UserService {

    User findById(long id);

    User findByEmail(String email);

    User getUserById(long id);

    ArrayList<User> findAll();

    User create(UserRegistrationDTO userRegistrationDTO);

    User update(long id, UserUpdateDTO userUpdateDTO);

    User changePassword(long id, UserPasswordDTO userPasswordDTO);
}
