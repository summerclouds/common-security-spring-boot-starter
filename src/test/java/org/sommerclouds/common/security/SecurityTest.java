package org.sommerclouds.common.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.summerclouds.common.core.internal.SpringSummerCloudsCoreAutoConfiguration;
import org.summerclouds.common.core.security.ISecurity;
import org.summerclouds.common.core.security.ISubject;
import org.summerclouds.common.core.security.ISubjectEnvironment;
import org.summerclouds.common.core.tool.MSecurity;
import org.summerclouds.common.junit.TestCase;
import org.summerclouds.common.security.internal.SpringSummerCloudsSecurityAutoConfiguration;
import org.summerclouds.common.security.realm.RealmManager;

@SpringBootTest(classes = {
		RealmManager.class, 
		RealmTestConfiguration.class, 
		SpringSummerCloudsCoreAutoConfiguration.class,
		SpringSummerCloudsSecurityAutoConfiguration.class})
public class SecurityTest extends TestCase {

	@Test
	public void testAsSubject() {
		System.out.println(MSecurity.getCurrent());
		assertNull(MSecurity.getCurrent());
		
		try (ISubjectEnvironment sudo = MSecurity.asSubject("user")) {
			System.out.println(MSecurity.getCurrent());
			assertEquals("user", MSecurity.getCurrent().getName());
		}
		
		System.out.println(MSecurity.getCurrent());
		assertNull(MSecurity.getCurrent());
	}
	
	@Test
	public void testGetSubject() {
		ISubject admin = MSecurity.getSubject("admin");
		assertEquals("admin", admin.getName());
	}

	@Test
	public void testHasAccess() {
		try (ISubjectEnvironment sudo = MSecurity.asSubject("user")) {
			ISecurity sec = MSecurity.get();
			assertFalse(sec.hasPermission("a:b:c"));
			assertFalse(sec.hasPermission("role:*:admin"));
			
			assertTrue(sec.hasPermission("web:get:/secret"));
			assertTrue(sec.hasPermission("role:*:user"));

			assertTrue(sec.hasRole("user"));
			assertFalse(sec.hasRole("admin"));
		}
		
		try (ISubjectEnvironment sudo = MSecurity.asSubject("user")) {
			ISubject sec = sudo.getSubject();
			assertFalse(sec.hasPermission("a:b:c"));
			assertFalse(sec.hasPermission("role:*:admin"));
			
			assertTrue(sec.hasPermission("web:get:/secret"));
			assertTrue(sec.hasPermission("role:*:user"));

			assertTrue(sec.hasRole("user"));
			assertFalse(sec.hasRole("admin"));
		}

	}

}
