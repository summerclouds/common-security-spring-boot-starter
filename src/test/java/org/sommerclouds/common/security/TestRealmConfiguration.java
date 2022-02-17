package org.sommerclouds.common.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.summerclouds.common.security.realm.MemoryRoleAclRealm;
import org.summerclouds.common.security.realm.MemoryRoleRealm;
import org.summerclouds.common.security.realm.MemoryUserAclRealm;
import org.summerclouds.common.security.realm.MemoryUserRealm;
import org.summerclouds.common.security.realm.MemoryUserRolesRealm;
import org.summerclouds.common.security.realm.Realm;

public class TestRealmConfiguration {

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }    

    @Bean
    public Realm userRealm() {
    	return new MemoryUserRealm().add("user", "user").add("admin", "admin");
    }

    @Bean
    public Realm userRolesRealm() {
    	return new MemoryUserRolesRealm().add("user", "USER").add("admin", "ADMIN");
    }
    
    @Bean
    public Realm userAclRealm() {
    	return new MemoryUserAclRealm().add("admin", "*");
    }
    
    @Bean
    public Realm roleAclRealm() {
    	return new MemoryRoleAclRealm().add("user", "web:*:/secret");
    }
    
    @Bean
    public Realm roleRealm() {
    	return new MemoryRoleRealm().add("admin").add("user");
    }

}
