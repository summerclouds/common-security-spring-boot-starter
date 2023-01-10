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
package org.summerclouds.common.security.permissions;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.summerclouds.common.core.tool.MSecurity;

public class RoleAceVoter implements AccessDecisionVoter<Object> {

    public static final String ROLE_PREFIX = "ROLE_";

    private String rolePrefixUpper = "ROLE_";
    private String rolePrefixLower = "role_";
    public static final String ROLE_ACE =
            "role" + MSecurity.PART_DIVIDER_TOKEN + "access" + MSecurity.PART_DIVIDER_TOKEN;
    private boolean legacy = true;

    public String getRolePrefix() {
        return this.rolePrefixUpper;
    }

    /**
     * Allows the default role prefix of <code>ROLE_</code> to be overridden. May be set to an empty
     * value, although this is usually not desirable.
     *
     * @param rolePrefix the new prefix
     */
    public void setRolePrefix(String rolePrefix) {
        this.rolePrefixUpper = rolePrefix.toUpperCase();
        this.rolePrefixLower = rolePrefix.toLowerCase();
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        String value = toString(attribute);
        return value != null
                && (value.startsWith(rolePrefixUpper) || value.startsWith(rolePrefixLower));
    }

    public String toString(ConfigAttribute attribute) {
        String value = null;
        if (attribute.getAttribute() != null) {
            value = attribute.getAttribute();
        } else {
            String str = attribute.toString();
            if (str != null && str.startsWith("hasAuthority('")) {
                value = str.substring(14, str.length() - 2);
            }
        }
        return value;
    }

    /**
     * This implementation supports any type of class, because it does not query the presented
     * secure object.
     *
     * @param clazz the secure object
     * @return always <code>true</code>
     */
    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public int vote(
            Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        if (authentication == null) {
            return ACCESS_DENIED;
        }
        int result = ACCESS_ABSTAIN;
        Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
        for (ConfigAttribute attribute : attributes) {
            if (this.supports(attribute)) {
                String rolename =
                        toString(attribute).substring(rolePrefixUpper.length()).toLowerCase();
                String roleAsPermission = ROLE_ACE + rolename;
                result = ACCESS_DENIED;
                // Attempt to find a matching granted authority
                for (GrantedAuthority authority : authorities) {
                    if (authority instanceof Permissions
                            && ((Permissions) authority).hasPermission(roleAsPermission))
                        return ACCESS_GRANTED;
                    else if (legacy && rolename.equalsIgnoreCase(authority.getAuthority())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }
        return result;
    }

    Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
        return authentication.getAuthorities();
    }
}
