package org.sommerclouds.common.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.summerclouds.common.core.internal.SpringSummerCloudsCoreAutoConfiguration;
import org.summerclouds.common.security.internal.SpringSummerCloudsSecurityAutoConfiguration;
import org.summerclouds.common.security.permissions.PermSet;
import org.summerclouds.common.security.realm.RealmManager;
import org.summerclounds.common.junit.TestCase;

@SpringBootTest(classes = {
		RealmManager.class, 
		RealmTestConfiguration.class, 
		SpringSummerCloudsCoreAutoConfiguration.class,
		SpringSummerCloudsSecurityAutoConfiguration.class})
public class RealmTest extends TestCase {

	@Autowired
	RealmManager manager;
	
	@Test
	public void realmTest() {
		UserDetails admin = manager.loadUserByUsername("admin");
		assertNotNull(admin);
		{	
			Collection<? extends GrantedAuthority> auth = admin.getAuthorities();
			assertNotNull(auth);
			assertEquals(1, auth.size());
			GrantedAuthority entry = auth.iterator().next();
			assertTrue(entry instanceof PermSet);
			PermSet acl = (PermSet)entry;
			log().i("ADMIN ACL",acl);
			assertTrue(acl.hasPermission("a:b:c"));
		}		
		UserDetails user = manager.loadUserByUsername("user");
		assertNotNull(user);
		{	
			Collection<? extends GrantedAuthority> auth = user.getAuthorities();
			assertNotNull(auth);
			assertEquals(1, auth.size());
			GrantedAuthority entry = auth.iterator().next();
			assertTrue(entry instanceof PermSet);
			PermSet acl = (PermSet)entry;
			log().i("USER ACL",acl);
			assertFalse(acl.hasPermission("a:b:c"));
			assertFalse(acl.hasPermission("role:*:admin"));
			
			assertTrue(acl.hasPermission("web:get:/secret"));
			assertTrue(acl.hasPermission("role:*:user"));
		}		
		
		try {
			manager.loadUserByUsername("other");
			fail("Username should not be found");
		} catch (UsernameNotFoundException e) {
			e.printStackTrace();
		}

	}
	
	
}
