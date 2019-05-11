package com.businesssystemssecurity.proj.seeder.data;

import com.businesssystemssecurity.proj.domain.Authority;
import com.businesssystemssecurity.proj.domain.User;
import com.businesssystemssecurity.proj.domain.UserAuthority;
import com.businesssystemssecurity.proj.exception.EntityNotFoundException;
import com.businesssystemssecurity.proj.repository.AuthorityRepository;
import com.businesssystemssecurity.proj.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.transaction.Transactional;
import java.util.HashMap;
import java.util.Optional;

@Component
public class UserTableSeed {

    private Logger logger = LoggerFactory.getLogger(UserTableSeed.class);

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthorityRepository authorityRepository;

    @Autowired
    private UserRepository userRepository;


    public static class UserSeedData {
        public String email;
        public String pass;
        public String firstname;
        public String lastname;
        public String authority;

        public UserSeedData(String email, String pass, String firstname, String lastname, String authority) {
            this.email = email;
            this.pass = pass;
            this.firstname = firstname;
            this.lastname = lastname;
            this.authority = authority;
        }
    }

    // Add admin user #1
    public final static String ADMIN1_EMAIL = "admin1@gmail.com";
    public final static String ADMIN1_PASSWORD = "123456";
    public final static String ADMIN1_FIRSTNAME = "Đura";
    public final static String ADMIN1_LASTNAME = "Jakšić";
    public final static String ADMIN1_AUTHORITY = "admin";
    public final static long   ADMIN1_AUTHORITY_ID = 1L;
    public final static UserSeedData ADMIN1 = new UserSeedData(
            ADMIN1_EMAIL,
            ADMIN1_PASSWORD,
            ADMIN1_FIRSTNAME,
            ADMIN1_LASTNAME,
            ADMIN1_AUTHORITY
    );

    // Add admin user #2
    public final static String ADMIN2_EMAIL = "admin1@gmail.com";
    public final static String ADMIN2_PASSWORD = "123456";
    public final static String ADMIN2_FIRSTNAME = "Desanka";
    public final static String ADMIN2_LASTNAME = "Maksimovć";
    public final static String ADMIN2_AUTHORITY = "admin";
    public final static long   ADMIN2_AUTHORITY_ID = 1L;
    public final static UserSeedData ADMIN2 = new UserSeedData(
            ADMIN2_EMAIL,
            ADMIN2_PASSWORD,
            ADMIN2_FIRSTNAME,
            ADMIN2_LASTNAME,
            ADMIN2_AUTHORITY
    );

    // Add regular user #1
    public final static String REGULAR1_EMAIL = "regular1@gmail.com";
    public final static String REGULAR1_PASSWORD = "123456";
    public final static String REGULAR1_FIRSTNAME = "Pera";
    public final static String REGULAR1_LASTNAME = "Perić";
    public final static String REGULAR1_AUTHORITY = "regular";
    public final static long   REGULAR1_AUTHORITY_ID = 2L;
    public final static UserSeedData REGULAR1 = new UserSeedData(
            REGULAR1_EMAIL,
            REGULAR1_PASSWORD,
            REGULAR1_FIRSTNAME,
            REGULAR1_LASTNAME,
            REGULAR1_AUTHORITY
    );

    // Add regular user #2
    public final static String REGULAR2_EMAIL = "regular2@gmail.com";
    public final static String REGULAR2_PASSWORD = "123456";
    public final static String REGULAR2_FIRSTNAME = "Marko";
    public final static String REGULAR2_LASTNAME = "Marković";
    public final static String REGULAR2_AUTHORITY = "regular";
    public final static long   REGULAR2_AUTHORITY_ID = 2L;
    public final static UserSeedData REGULAR2 = new UserSeedData(
            REGULAR2_EMAIL,
            REGULAR2_PASSWORD,
            REGULAR2_FIRSTNAME,
            REGULAR2_LASTNAME,
            REGULAR2_AUTHORITY
    );



    public final static HashMap<String, UserSeedData> USERDATA = new HashMap<>();

    @PostConstruct
    public void init() {
        ADMIN1.pass = passwordEncoder.encode(ADMIN1.pass);
        ADMIN2.pass = passwordEncoder.encode(ADMIN2.pass);

        REGULAR1.pass = passwordEncoder.encode(REGULAR1.pass);
        REGULAR2.pass = passwordEncoder.encode(REGULAR2.pass);

        USERDATA.put("admin1", ADMIN1);
        USERDATA.put("admin2", ADMIN2);
        USERDATA.put("regular1", REGULAR1);
        USERDATA.put("regular2", REGULAR2);
    }

    public UserSeedData getEntry(String key) {
        return USERDATA.get(key);
    }

    public int getDataSize() {
        return USERDATA.size();
    }

    @Transactional
    public void seed(String dataIndex) {

        if (!USERDATA.containsKey(dataIndex)) {
            logger.error("Data index " + dataIndex + "not found! ");
            return;
        }

        UserSeedData user = USERDATA.get(dataIndex);

        Optional<User> found_user = userRepository.findByEmail(user.email);

        if (found_user.isPresent()) {
            logger.info("User with following email " + user.email + " already added");
            return;
        }
        User new_user = new User(user.email, user.pass, user.firstname, user.lastname);

        UserAuthority ua = new UserAuthority();

        Optional<Authority> authority = authorityRepository.findByName(user.authority);

        // Check existence;
        if (!authority.isPresent()) {
            logger.error("Seeding order is violated, no enough data to build user");
            return;
        }

        ua.setAuthority(authority.get());
        ua.setUser(new_user);

        new_user.getUserAuthorities().add(ua);
        userRepository.save(new_user);

        logger.info("Added user: " + new_user);
    }

    @Transactional
    public User getUser(String dataIndex) {
        if (!USERDATA.containsKey(dataIndex)) {
            logger.error("Data index " + dataIndex + "not found! ");
        }

        UserSeedData user = USERDATA.get(dataIndex);
        Optional<User> found_user = userRepository.findByEmail(user.email);

        if (found_user.isPresent()) {
            return found_user.get();
        } else {
            throw new EntityNotFoundException(UserTableSeed.class, "email", user.email);
        }
    }
}
