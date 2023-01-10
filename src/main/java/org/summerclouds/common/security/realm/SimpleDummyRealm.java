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
package org.summerclouds.common.security.realm;

import java.util.ArrayList;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.summerclouds.common.core.tool.MSpring;
import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.security.permissions.PermSet;

/**
 * This realm simply define two users 1. user 2. admin
 *
 * @author mikehummel
 */
public class SimpleDummyRealm implements UserRealm {

    RealmUser guest;
    RealmUser user;
    RealmUser admin;

    @Autowired private PasswordEncoder encoder;

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public User getUser(String username) {

        if ("guest".equals(username)) {
            return getUserGuest();
        }
        if ("user".equals(username)) {
            return getUserUser();
        }
        if ("admin".equals(username)) {
            return getUserAdmin();
        }
        return null;
    }

    private synchronized User getUserGuest() {
        if (guest != null) return guest;

        ArrayList<GrantedAuthority> auth = new ArrayList<>();
        guest =
                new RealmUser(
                        this, "guest", UUID.randomUUID().toString(), true, true, true, true, auth);
        return guest;
    }

    private synchronized User getUserUser() {
        if (user != null) return user;

        String password = MSpring.getValue("spring.security.user.password");
        if (password == null) {
            password = UUID.randomUUID().toString();
            System.out.println("Generated user password " + password);
        }
        ArrayList<GrantedAuthority> auth = new ArrayList<>();
        String aclStr = MSpring.getValue("spring.security.user.permissions");
        if (aclStr != null) {
            PermSet permSet = new PermSet(aclStr);
            auth.add(permSet);
        } else System.out.println("User permissions 'spring.security.user.permissions' not found");
        String authStr = MSpring.getValue("spring.security.user.authorities");
        if (authStr != null)
            for (String a : authStr.split(","))
                if (MString.isSetTrim(a)) auth.add(new SimpleGrantedAuthority(a));
                else
                    System.out.println(
                            "User authorities 'spring.security.user.authorities' not found");
        //		if (auth.size() == 0) // add dummy auth
        //			auth.add(new SimpleGrantedAuthority(UUID.randomUUID().toString()));
        user = new RealmUser(this, "user", encoder.encode(password), true, true, true, true, auth);
        user.setDoNotEraseCredentials(true);
        return user;
    }

    private synchronized User getUserAdmin() {
        if (admin != null) return admin;

        String password = MSpring.getValue("spring.security.user.password");
        if (password == null) {
            password = UUID.randomUUID().toString();
            System.out.println("Generated admin password " + password);
        }
        ArrayList<GrantedAuthority> auth = new ArrayList<>();
        PermSet permSet = new PermSet("*");
        auth.add(permSet);

        admin =
                new RealmUser(
                        this, "admin", encoder.encode(password), true, true, true, true, auth);
        admin.setDoNotEraseCredentials(true);
        return admin;
    }
}
