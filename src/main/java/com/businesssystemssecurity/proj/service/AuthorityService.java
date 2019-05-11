package com.businesssystemssecurity.proj.service;

import com.businesssystemssecurity.proj.domain.Authority;

import java.util.ArrayList;

public interface AuthorityService {

    Authority findById(long id);

    ArrayList<Authority> findAll();
}
