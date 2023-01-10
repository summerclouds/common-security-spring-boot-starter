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

import java.util.Map;
import java.util.Set;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.tool.MSpring;
import org.summerclouds.common.core.tool.MTracing;
import org.summerclouds.common.core.tracing.IScope;
import org.summerclouds.common.security.permissions.PermSet;

public class RealmManager extends MLog implements UserDetailsService {

    //	@Autowired
    private Map<String, Realm> realms;

    protected synchronized void loadRealms() {
        if (realms != null) return;
        realms = MSpring.getBeansOfType(Realm.class);
        log().d("loaded realms", realms);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Assert.hasText(username, "Usernam can't be empty");
        try (IScope scope = MTracing.enter("load user", "username", username)) {
            username = RealmUtil.normalize(username);
            loadRealms();
            if (realms == null) return null;
            for (Map.Entry<String, Realm> realm : realms.entrySet()) {
                try {
                    if (realm.getValue().isEnabled() && realm.getValue() instanceof UserRealm) {
                        User user = ((UserRealm) realm.getValue()).getUser(username);
                        if (user != null) {
                            log().d("load user {1} from realm {2}", username, realm.getKey());
                            return user;
                        }
                    }
                } catch (Throwable t) {
                    log().w("can't load user from realm {1}", realm.getKey(), t);
                }
            }
            throw new UsernameNotFoundException("user not found " + username);
        }
    }

    public PermSet loadAclForUsername(String username) {
        if (!StringUtils.hasText(username)) return null;
        username = RealmUtil.normalize(username);
        loadRealms();
        if (realms == null) return null;
        for (Map.Entry<String, Realm> realm : realms.entrySet()) {
            try {
                if (realm.getValue().isEnabled() && realm.getValue() instanceof UserAclRealm) {
                    PermSet acl = ((UserAclRealm) realm.getValue()).getAclForUser(username);
                    if (acl != null) {
                        log().d("load acl for user {1} from realm {2}", username, realm.getKey());
                        return acl;
                    }
                }
            } catch (Throwable t) {
                log().w("can't load acl from realm {1}", realm.getKey(), t);
            }
        }
        return null;
    }

    public Role loadRoleByRolename(String rolename) {
        if (!StringUtils.hasText(rolename)) return null;
        rolename = RealmUtil.normalize(rolename);
        loadRealms();
        if (realms == null) return null;
        for (Map.Entry<String, Realm> realm : realms.entrySet()) {
            try {
                if (realm.getValue().isEnabled() && realm.getValue() instanceof RoleRealm) {
                    Role role = ((RoleRealm) realm.getValue()).getRole(rolename);
                    if (role != null) {
                        log().d("load role {1} from realm {2}", rolename, realm.getKey());
                        return role;
                    }
                }
            } catch (Throwable t) {
                log().w("can't load acl from realm {1}", realm.getKey(), t);
            }
        }
        return null;
    }

    public PermSet loadAclForRole(String rolename) {
        if (!StringUtils.hasText(rolename)) return null;
        rolename = RealmUtil.normalize(rolename);
        loadRealms();
        if (realms == null) return null;
        for (Map.Entry<String, Realm> realm : realms.entrySet()) {
            try {
                if (realm.getValue().isEnabled() && realm.getValue() instanceof RoleAclRealm) {
                    PermSet acl = ((RoleAclRealm) realm.getValue()).getAclforRole(rolename);
                    if (acl != null) {
                        log().d("load acl for role {1} from realm {2}", rolename, realm.getKey());
                        return acl;
                    }
                }
            } catch (Throwable t) {
                log().w("can't load acl from realm {1}", realm.getKey(), t);
            }
        }
        return null;
    }

    public Set<String> loadRolesByUsername(String username) {
        if (!StringUtils.hasText(username)) return null;
        username = RealmUtil.normalize(username);
        loadRealms();
        if (realms == null) return null;
        for (Map.Entry<String, Realm> realm : realms.entrySet()) {
            try {
                if (realm.getValue().isEnabled() && realm.getValue() instanceof UserRoleRealm) {
                    Set<String> roles =
                            ((UserRoleRealm) realm.getValue()).getRolesForUser(username);
                    if (roles != null) {
                        log().d("load roles for user {1} from realm {2}", username, realm.getKey());
                        return roles;
                    }
                }
            } catch (Throwable t) {
                log().w("can't load roles from realm {1}", realm.getKey(), t);
            }
        }
        return null;
    }

    public void loadUserData(String username, Map<String, String> data) {
        if (!StringUtils.hasText(username)) return;
        username = RealmUtil.normalize(username);
        loadRealms();
        if (realms == null) return;
        for (Map.Entry<String, Realm> realm : realms.entrySet()) {
            try {
                if (realm.getValue().isEnabled() && realm.getValue() instanceof UserDataRealm) {
                    UserData d = ((UserDataRealm) realm).getUserData(username);
                    data.putAll(d.getUserData());
                }
            } catch (Throwable t) {
                log().w("can't load user data from realm {1}", realm.getKey(), t);
            }
        }
    }
}
