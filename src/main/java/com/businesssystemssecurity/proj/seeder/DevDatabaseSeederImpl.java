package com.businesssystemssecurity.proj.seeder;

import com.businesssystemssecurity.proj.seeder.data.AuthorityTableSeed;
import com.businesssystemssecurity.proj.seeder.data.PermissionTableSeed;
import com.businesssystemssecurity.proj.seeder.data.UserTableSeed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
@Profile("dev")
public class DevDatabaseSeederImpl implements DatabaseSeeder {

    @Autowired
    AuthorityTableSeed authorityTableSeed;

    @Autowired
    PermissionTableSeed permissionTableSeed;

    @Autowired
    UserTableSeed userTableSeed;

    @Override
    @EventListener
    public void seed(ContextRefreshedEvent event) {
        this.authorityTableSeed.seed();
        this.permissionTableSeed.seed();

        userTableSeed.seed("admin");
    }
}
