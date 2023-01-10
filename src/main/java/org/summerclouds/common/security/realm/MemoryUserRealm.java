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
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.summerclouds.common.security.permissions.PermSet;

public class MemoryUserRealm extends AbstractUserRealm {

    @Autowired private PasswordEncoder encoder;

    private HashMap<String, String> users = new HashMap<>();

    @Override
    public boolean isEnabled() {
        return !users.isEmpty();
    }

    @Override
    protected User createUser(String username, PermSet acl, Map<String, String> data) {
        String password = users.get(username);
        if (password == null) return null;
        ArrayList<GrantedAuthority> list = new ArrayList<>(1);
        list.add(acl);
        return new DataUser(username, encoder.encode(password), list, data);
    }

    public MemoryUserRealm add(String name, String password) {
        users.put(name, password);
        return this;
    }
}
