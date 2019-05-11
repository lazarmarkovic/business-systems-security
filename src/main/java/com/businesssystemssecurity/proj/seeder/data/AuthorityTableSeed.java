package com.businesssystemssecurity.proj.seeder.data;

import com.businesssystemssecurity.proj.domain.Authority;
import com.businesssystemssecurity.proj.repository.AuthorityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.transaction.Transactional;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Component
public class AuthorityTableSeed {

    @Autowired
    private AuthorityRepository authorityRepository;

    private Logger logger = LoggerFactory.getLogger(AuthorityTableSeed.class);

    public static final String ADMIN_AUTHORITY_NAME = "admin";
    public static final String REGULAR_AUTHORITY_NAME = "regular";

    private final Map<String, String> DATA = new HashMap<>();


    @PostConstruct
    public void init(){
        DATA.put("admin", ADMIN_AUTHORITY_NAME);
        DATA.put("regular", REGULAR_AUTHORITY_NAME);
    }

    @Transactional
    public void seed(String dataIndex) {
        if (!this.DATA.containsKey(dataIndex)) {
            logger.error("Data index " + dataIndex + " not found!");
            return;
        }

        String authority = DATA.get(dataIndex);

        Optional<Authority> found_role = authorityRepository.findByName(authority);
        if (found_role.isPresent()) {
            logger.info("Authority " + authority + "already added.");
            return;
        }

        Authority new_authority = new Authority();
        new_authority.setName(authority);
        authorityRepository.save(new_authority);
        logger.info("Added authority: " + new_authority);
    }

}
