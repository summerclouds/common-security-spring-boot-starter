package org.sommerclouds.common.security;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.summerclouds.common.core.security.ISecurity;
import org.summerclouds.common.security.SecurityService;
import org.summerclouds.common.security.permissions.ResourceAceVoter;
import org.summerclouds.common.security.permissions.RoleAceVoter;
import org.summerclouds.common.security.realm.MemoryRoleAclRealm;
import org.summerclouds.common.security.realm.MemoryRoleRealm;
import org.summerclouds.common.security.realm.MemoryUserAclRealm;
import org.summerclouds.common.security.realm.MemoryUserRealm;
import org.summerclouds.common.security.realm.MemoryUserRolesRealm;
import org.summerclouds.common.security.realm.Realm;

public class RealmTestConfiguration {

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

    @Bean
    public ISecurity security() {
    	return new SecurityService();
    }
    
	@Bean
	public AccessDecisionManager accessDecisionManager() {
		
	    List<AccessDecisionVoter<? extends Object>> decisionVoters 
	      = Arrays.asList(
  		    new ResourceAceVoter(),
	        new WebExpressionVoter(),
	        new RoleAceVoter(), // instead of RoleVoter()
	        new AuthenticatedVoter()
	        );
	    return new AffirmativeBased(decisionVoters);
	}
    
}
