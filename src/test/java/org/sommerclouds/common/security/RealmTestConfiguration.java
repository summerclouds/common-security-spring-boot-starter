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

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.summerclouds.common.security.permissions.ResourceAceVoter;
import org.summerclouds.common.security.permissions.RoleAceVoter;
import org.summerclouds.common.security.realm.MemoryRoleAclRealm;
import org.summerclouds.common.security.realm.MemoryRoleRealm;
import org.summerclouds.common.security.realm.MemoryUserAclRealm;
import org.summerclouds.common.security.realm.MemoryUserRealm;
import org.summerclouds.common.security.realm.MemoryUserRolesRealm;
import org.summerclouds.common.security.realm.Realm;

public class RealmTestConfiguration {

    //    @Bean
    //    public PasswordEncoder encoder() {
    //        return new BCryptPasswordEncoder();
    //    }

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

    //    @Bean
    //    public ISecurity security() {
    //    	return new SecurityService();
    //    }

    @Bean
    public AccessDecisionManager accessDecisionManager() {

        List<AccessDecisionVoter<? extends Object>> decisionVoters =
                Arrays.asList(
                        new ResourceAceVoter(),
                        new WebExpressionVoter(),
                        new RoleAceVoter(), // instead of RoleVoter()
                        new AuthenticatedVoter());
        return new AffirmativeBased(decisionVoters);
    }
}
