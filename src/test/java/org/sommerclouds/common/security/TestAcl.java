package org.sommerclouds.common.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.summerclouds.common.core.tool.MCollection;
import org.summerclouds.common.security.permissions.Acl;
import org.summerclouds.common.security.permissions.WildcardAce;
import org.summerclounds.common.junit.TestCase;

public class TestAcl extends TestCase {

	@Test
	public void testDouble() {
		// positive tests
		{
			Acl acl = new Acl("test:test:test","test:test:test");
			List<WildcardAce> list = MCollection.toList(acl);
			assertEquals(1, list.size());
		}
		{
			Acl acl = new Acl("test:test:test:Description a","test:test:test:Description b");
			List<WildcardAce> list = MCollection.toList(acl);
			assertEquals(1, list.size());
		}
		{
			Acl acl = new Acl("test:test","test:test:*");
			List<WildcardAce> list = MCollection.toList(acl);
			assertEquals(1, list.size());
		}
		// negative tests
		{
			Acl acl = new Acl("test1:test:test","test2:test:test");
			List<WildcardAce> list = MCollection.toList(acl);
			assertEquals(2, list.size());
		}
		{
			Acl acl = new Acl("test:test1:test","test:test2:test");
			List<WildcardAce> list = MCollection.toList(acl);
			assertEquals(2, list.size());
		}
		{
			Acl acl = new Acl("test:test:test1","test:test:test2");
			List<WildcardAce> list = MCollection.toList(acl);
			assertEquals(2, list.size());
		}
	}
	
	@Test
	public void testWildcard() {
		{
			Acl acl = new Acl("test:test:*");
			assertTrue( acl.hasPermission("test:test:test"));
			assertTrue( acl.hasPermission("test:test:test1"));
			assertTrue( acl.hasPermission("test:test:test2"));

			assertFalse( acl.hasPermission("test:test1:test"));
			assertFalse( acl.hasPermission("test1:test:test"));
		}
		{
			Acl acl = new Acl("test:test");
			assertTrue( acl.hasPermission("test:test:test"));
			assertTrue( acl.hasPermission("test:test:test1"));
			assertTrue( acl.hasPermission("test:test:test2"));

			assertFalse( acl.hasPermission("test:test1:test"));
			assertFalse( acl.hasPermission("test1:test:test"));
		}
		{
			Acl acl = new Acl("test");
			assertTrue( acl.hasPermission("test:test:test"));
			assertTrue( acl.hasPermission("test:test:test1"));
			assertTrue( acl.hasPermission("test:test:test2"));
			assertTrue( acl.hasPermission("test:test1:test"));
			
			assertFalse( acl.hasPermission("test1:test:test"));
		}
		{
			Acl acl = new Acl("test:*:test");
			assertTrue( acl.hasPermission("test:test:test"));
			assertTrue( acl.hasPermission("test:test1:test"));
			assertTrue( acl.hasPermission("test:test2:test"));

			assertFalse( acl.hasPermission("test:test:test1"));
			assertFalse( acl.hasPermission("test1:test:test"));
		}
		{
			Acl acl = new Acl("*:test:test","test:test:test");
			assertTrue( acl.hasPermission("test:test:test"));
			assertTrue( acl.hasPermission("test1:test:test"));
			assertTrue( acl.hasPermission("test2:test:test"));

			assertFalse( acl.hasPermission("test:test1:test"));
			assertFalse( acl.hasPermission("test1:test:test1"));
		}
	}
	
	@Test
	public void testEnhanceWildcard() {
		{ // enhance wildcard for instance
			Acl acl = new Acl("test:test:test*");
			assertTrue( acl.hasPermission("test:test:test"));
			assertTrue( acl.hasPermission("test:test:test1"));
			assertTrue( acl.hasPermission("test:test:test2"));
	
			assertFalse( acl.hasPermission("test:test:bla"));
			assertFalse( acl.hasPermission("test:bla:test"));
		}
		{ // enhance wildcard for action
			Acl acl = new Acl("test:test*:test");
			assertTrue( acl.hasPermission("test:test:test"));
			assertTrue( acl.hasPermission("test:test1:test"));
			assertTrue( acl.hasPermission("test:test2:test"));
	
			assertFalse( acl.hasPermission("test:bla:test"));
			assertFalse( acl.hasPermission("test:test:bla"));
		}
		{ // no enhancing wildcard for object
			Acl acl = new Acl("test*:test:test");
			assertTrue( acl.hasPermission("test*:test:test"));
			
			assertFalse( acl.hasPermission("test:test:test"));
			assertFalse( acl.hasPermission("test1:test:test"));
			assertFalse( acl.hasPermission("test2:test:test"));
			assertFalse( acl.hasPermission("test:bla:test"));
			assertFalse( acl.hasPermission("test:test:bla"));
		}
	
	}

	@Test
	public void testFullWildcard() {
		Acl acl = new Acl("*");
		assertTrue( acl.hasPermission("test:test:test"));
		assertTrue( acl.hasPermission("test:test:test1"));
		assertTrue( acl.hasPermission("test:test:test2"));
		assertTrue( acl.hasPermission("test:test:test"));
		assertTrue( acl.hasPermission("test:test1:test"));
		assertTrue( acl.hasPermission("test:test2:test"));
		assertTrue( acl.hasPermission("test:test:test"));
		assertTrue( acl.hasPermission("test1:test:test"));
		assertTrue( acl.hasPermission("test2:test:test"));
		assertTrue( acl.hasPermission("test:bla:test"));
		assertTrue( acl.hasPermission("test:test:bla"));
	}
	
	
	@Test
	public void testDistinctWildcard() {
		Acl acl = new Acl("test:test:test");

		assertTrue( acl.hasPermission("test:test:test"));
		assertTrue( acl.hasPermission("test:test:*"));
		assertTrue( acl.hasPermission("test:*:test"));
		assertTrue( acl.hasPermission("*:test:test"));
		assertTrue( acl.hasPermission("test"));
		assertTrue( acl.hasPermission("test:test"));
		assertTrue( acl.hasPermission("*:*:test"));
		assertTrue( acl.hasPermission("*"));
		assertTrue( acl.hasPermission("*:*:*"));
		assertTrue( acl.hasPermission("*:*"));

		assertFalse( acl.hasPermission("test:test:te*"));
		assertFalse( acl.hasPermission("test:te*:test"));
		assertFalse( acl.hasPermission("test:bla:*"));
		assertFalse( acl.hasPermission("test:*:bla"));
		assertFalse( acl.hasPermission("*:bla:test"));

	}

}
