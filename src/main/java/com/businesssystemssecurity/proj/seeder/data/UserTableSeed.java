package com.businesssystemssecurity.proj.seeder.data;

import com.businesssystemssecurity.proj.domain.*;
import com.businesssystemssecurity.proj.repository.AuthorityRepository;
import com.businesssystemssecurity.proj.repository.PermissionRepository;
import com.businesssystemssecurity.proj.repository.UserRepository;
import com.businesssystemssecurity.proj.repository.connectors.UserAuthorityRepository;
import com.businesssystemssecurity.proj.repository.connectors.UserPermissionRepository;
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
    private PermissionRepository permissionRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserAuthorityRepository userAuthorityRepository;

    @Autowired
    private UserPermissionRepository userPermissionRepository;


    public static class UserSeedData {
        public String email;
        public String password;
        public String firstName;
        public String lastName;
        public long authorityID;
        public long[] permissionIDs;

        public UserSeedData(String email, String pass, String firstName, String lastName, long authorityID, long[] permissionIDs) {
            this.email = email;
            this.password = pass;
            this.firstName = firstName;
            this.lastName = lastName;
            this.authorityID = authorityID;
            this.permissionIDs = permissionIDs;
        }
    }

    // Add admin user #1
    public final static String ADMIN_EMAIL = "admin@gmail.com";
    public final static String ADMIN_PASSWORD = "123456";
    public final static String ADMIN_FIRSTNAME = "Đura";
    public final static String ADMIN_LASTNAME = "Jakšić";
    public final static long   ADMIN_AUTHORITY_ID = 1L;
    public final static long[] ADMIN_PERMISSION_IDS = {1,2,3,4,5,6,7,8,9,10,11,12};
    public final static UserSeedData ADMIN = new UserSeedData(
            ADMIN_EMAIL,
            ADMIN_PASSWORD,
            ADMIN_FIRSTNAME,
            ADMIN_LASTNAME,
            ADMIN_AUTHORITY_ID,
            ADMIN_PERMISSION_IDS
    );

    public final static HashMap<String, UserSeedData> USERDATA = new HashMap<>();


    @PostConstruct
    public void init() {
        ADMIN.password = passwordEncoder.encode(ADMIN.password);
        USERDATA.put("admin", ADMIN);
    }

    @Transactional
    public void seed(String dataIndex) {

        if (!USERDATA.containsKey(dataIndex)) {
            logger.error("Data index " + dataIndex + "not found! ");
            return;
        }

        UserSeedData userSeedData = USERDATA.get(dataIndex);
        Optional<User> found_user = this.userRepository.findByEmail(userSeedData.email);

        if (found_user.isPresent()) {
            logger.info("User with following email " + userSeedData.email + " already added");
            return;
        }
        User new_user = new User(
                userSeedData.email,
                userSeedData.password,
                userSeedData.firstName,
                userSeedData.lastName,
                false
        );

        UserAuthority ua = new UserAuthority();
        Optional<Authority> authority = this.authorityRepository.findById(userSeedData.authorityID);

        // Check existence of authority
        if (!authority.isPresent()) {
            logger.error("Seeding order is violated, no enough data to build user");
            return;
        }
        ua.setAuthority(authority.get());
        ua.setUser(new_user);
        this.userAuthorityRepository.save(ua);

        for (long permissionID : userSeedData.permissionIDs) {
            UserPermission up = new UserPermission();
            Optional<Permission> permission = this.permissionRepository.findById(permissionID);

            // Check existence of permission
            if (!permission.isPresent()) {
                logger.error("Seeding order is violated, no enough data to build user");
                return;
            }
            up.setPermission(permission.get());
            up.setUser(new_user);
            this.userPermissionRepository.save(up);
        }

        logger.info("Added user: " + new_user);
    }
}
