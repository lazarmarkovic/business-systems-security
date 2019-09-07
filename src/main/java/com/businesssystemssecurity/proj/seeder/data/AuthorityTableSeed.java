package com.businesssystemssecurity.proj.seeder.data;

import com.businesssystemssecurity.proj.domain.Authority;
import com.businesssystemssecurity.proj.repository.AuthorityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.transaction.Transactional;
import java.util.Optional;

@Component
public class AuthorityTableSeed {

    @Autowired
    private AuthorityRepository authorityRepository;

    private Logger logger = LoggerFactory.getLogger(AuthorityTableSeed.class);

    public static final String ADMIN_AUTHORITY_NAME = "admin";
    public static final String REGULAR_AUTHORITY_NAME = "regular";


    public final String[] DATA = {
            ADMIN_AUTHORITY_NAME,
            REGULAR_AUTHORITY_NAME
    };


    @Transactional
    public void seed() {

       for (String authority_name : this.DATA) {
           Optional<Authority> found_role = authorityRepository.findByName(authority_name);
           if (found_role.isPresent()) {
               logger.info("Authority " + authority_name + "already added.");
               return;
           }

           Authority new_authority = new Authority();
           new_authority.setName(authority_name);
           authorityRepository.save(new_authority);
           logger.info("Added authority: " + new_authority);
       }
    }

}
