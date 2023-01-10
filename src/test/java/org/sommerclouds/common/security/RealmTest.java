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
import org.summerclouds.common.junit.TestCase;
import org.summerclouds.common.security.internal.SpringSummerCloudsSecurityAutoConfiguration;
import org.summerclouds.common.security.permissions.PermSet;
import org.summerclouds.common.security.realm.RealmManager;

@SpringBootTest(
        classes = {
            RealmManager.class,
            RealmTestConfiguration.class,
            SpringSummerCloudsCoreAutoConfiguration.class,
            SpringSummerCloudsSecurityAutoConfiguration.class
        })
public class RealmTest extends TestCase {

    @Autowired RealmManager manager;

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
            PermSet acl = (PermSet) entry;
            log().i("ADMIN ACL", acl);
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
            PermSet acl = (PermSet) entry;
            log().i("USER ACL", acl);
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
