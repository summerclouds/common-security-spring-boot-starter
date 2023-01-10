/**
 * Copyright (C) 2022 Mike Hummel (mh@mhus.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sommerclouds.common.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.summerclouds.common.core.tool.MCollection;
import org.summerclouds.common.junit.TestCase;
import org.summerclouds.common.security.permissions.PermSet;
import org.summerclouds.common.security.permissions.Perm;

public class AclTest extends TestCase {

    @Test
    public void testDouble() {
        // positive tests
        {
            PermSet acl = new PermSet("test:test:test", "test:test:test");
            List<Perm> list = MCollection.toList(acl);
            assertEquals(1, list.size());
        }
        {
            PermSet acl =
                    new PermSet("test:test:test:Description a", "test:test:test:Description b");
            List<Perm> list = MCollection.toList(acl);
            assertEquals(1, list.size());
        }
        {
            PermSet acl = new PermSet("test:test", "test:test:*");
            List<Perm> list = MCollection.toList(acl);
            assertEquals(1, list.size());
        }
        // negative tests
        {
            PermSet acl = new PermSet("test1:test:test", "test2:test:test");
            List<Perm> list = MCollection.toList(acl);
            assertEquals(2, list.size());
        }
        {
            PermSet acl = new PermSet("test:test1:test", "test:test2:test");
            List<Perm> list = MCollection.toList(acl);
            assertEquals(2, list.size());
        }
        {
            PermSet acl = new PermSet("test:test:test1", "test:test:test2");
            List<Perm> list = MCollection.toList(acl);
            assertEquals(2, list.size());
        }
    }

    @Test
    public void testWildcard() {
        {
            PermSet acl = new PermSet("test:test:*");
            assertTrue(acl.hasPermission("test:test:test"));
            assertTrue(acl.hasPermission("test:test:test1"));
            assertTrue(acl.hasPermission("test:test:test2"));

            assertFalse(acl.hasPermission("test:test1:test"));
            assertFalse(acl.hasPermission("test1:test:test"));
        }
        {
            PermSet acl = new PermSet("test:test");
            assertTrue(acl.hasPermission("test:test:test"));
            assertTrue(acl.hasPermission("test:test:test1"));
            assertTrue(acl.hasPermission("test:test:test2"));

            assertFalse(acl.hasPermission("test:test1:test"));
            assertFalse(acl.hasPermission("test1:test:test"));
        }
        {
            PermSet acl = new PermSet("test");
            assertTrue(acl.hasPermission("test:test:test"));
            assertTrue(acl.hasPermission("test:test:test1"));
            assertTrue(acl.hasPermission("test:test:test2"));
            assertTrue(acl.hasPermission("test:test1:test"));

            assertFalse(acl.hasPermission("test1:test:test"));
        }
        {
            PermSet acl = new PermSet("test:*:test");
            assertTrue(acl.hasPermission("test:test:test"));
            assertTrue(acl.hasPermission("test:test1:test"));
            assertTrue(acl.hasPermission("test:test2:test"));

            assertFalse(acl.hasPermission("test:test:test1"));
            assertFalse(acl.hasPermission("test1:test:test"));
        }
        {
            PermSet acl = new PermSet("*:test:test", "test:test:test");
            assertTrue(acl.hasPermission("test:test:test"));
            assertTrue(acl.hasPermission("test1:test:test"));
            assertTrue(acl.hasPermission("test2:test:test"));

            assertFalse(acl.hasPermission("test:test1:test"));
            assertFalse(acl.hasPermission("test1:test:test1"));
        }
    }

    @Test
    public void testEnhanceWildcard() {
        { // enhance wildcard for instance
            PermSet acl = new PermSet("test:test:test*");
            assertTrue(acl.hasPermission("test:test:test"));
            assertTrue(acl.hasPermission("test:test:test1"));
            assertTrue(acl.hasPermission("test:test:test2"));

            assertFalse(acl.hasPermission("test:test:bla"));
            assertFalse(acl.hasPermission("test:bla:test"));
        }
        { // enhance wildcard for action
            PermSet acl = new PermSet("test:test*:test");
            assertTrue(acl.hasPermission("test:test:test"));
            assertTrue(acl.hasPermission("test:test1:test"));
            assertTrue(acl.hasPermission("test:test2:test"));

            assertFalse(acl.hasPermission("test:bla:test"));
            assertFalse(acl.hasPermission("test:test:bla"));
        }
        { // no enhancing wildcard for object
            PermSet acl = new PermSet("test*:test:test");
            assertTrue(acl.hasPermission("test*:test:test"));

            assertFalse(acl.hasPermission("test:test:test"));
            assertFalse(acl.hasPermission("test1:test:test"));
            assertFalse(acl.hasPermission("test2:test:test"));
            assertFalse(acl.hasPermission("test:bla:test"));
            assertFalse(acl.hasPermission("test:test:bla"));
        }
    }

    @Test
    public void testFullWildcard() {
        PermSet acl = new PermSet("*");
        assertTrue(acl.hasPermission("test:test:test"));
        assertTrue(acl.hasPermission("test:test:test1"));
        assertTrue(acl.hasPermission("test:test:test2"));
        assertTrue(acl.hasPermission("test:test:test"));
        assertTrue(acl.hasPermission("test:test1:test"));
        assertTrue(acl.hasPermission("test:test2:test"));
        assertTrue(acl.hasPermission("test:test:test"));
        assertTrue(acl.hasPermission("test1:test:test"));
        assertTrue(acl.hasPermission("test2:test:test"));
        assertTrue(acl.hasPermission("test:bla:test"));
        assertTrue(acl.hasPermission("test:test:bla"));
    }

    @Test
    public void testDistinctWildcard() {
        PermSet acl = new PermSet("test:test:test");

        assertTrue(acl.hasPermission("test:test:test"));
        assertTrue(acl.hasPermission("test:test:*"));
        assertTrue(acl.hasPermission("test:*:test"));
        assertTrue(acl.hasPermission("*:test:test"));
        assertTrue(acl.hasPermission("test"));
        assertTrue(acl.hasPermission("test:test"));
        assertTrue(acl.hasPermission("*:*:test"));
        assertTrue(acl.hasPermission("*"));
        assertTrue(acl.hasPermission("*:*:*"));
        assertTrue(acl.hasPermission("*:*"));

        assertFalse(acl.hasPermission("test:test:te*"));
        assertFalse(acl.hasPermission("test:te*:test"));
        assertFalse(acl.hasPermission("test:bla:*"));
        assertFalse(acl.hasPermission("test:*:bla"));
        assertFalse(acl.hasPermission("*:bla:test"));
    }
}
