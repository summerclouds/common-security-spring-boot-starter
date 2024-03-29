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

import java.io.Serializable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;
import org.summerclouds.common.core.tool.MSecurity;

public class Perm implements GrantedAuthority, Serializable {

    private static final long serialVersionUID = 1L;

    private static final String WILDCARD2 =
            MSecurity.WILDCARD_TOKEN + MSecurity.PART_DIVIDER_TOKEN + MSecurity.WILDCARD_TOKEN;
    private static final String WILDCARD3 =
            MSecurity.WILDCARD_TOKEN
                    + MSecurity.PART_DIVIDER_TOKEN
                    + MSecurity.WILDCARD_TOKEN
                    + MSecurity.PART_DIVIDER_TOKEN
                    + MSecurity.WILDCARD_TOKEN;

    private String clazz;
    private boolean fullWildcard = false;
    private boolean wildcard = false;

    private Part actions; // action list

    private Part instances; // instance list

    private String description = "";

    public Perm(String wildcardString) {
        Assert.notNull(wildcardString, "wildcard string can't be null");
        // parse
        wildcardString = wildcardString.trim().toLowerCase();
        Assert.hasText(wildcardString, "wildcard string must be set");
        if (wildcardString.equals(MSecurity.WILDCARD_TOKEN)
                || wildcardString.equals(WILDCARD2)
                || wildcardString.equals(WILDCARD3)) {
            clazz = MSecurity.WILDCARD_TOKEN;
            actions = new Part(true);
            instances = new Part(true);
            fullWildcard = true;
            wildcard = true;
            return;
        }

        String[] parts = wildcardString.split(MSecurity.PART_DIVIDER_TOKEN, 4);
        Assert.isTrue(parts.length > 0, "minimum object name"); // paranoia

        clazz = parts[0].trim();
        wildcard = clazz.equals(MSecurity.WILDCARD_TOKEN);

        if (parts.length < 2) {
            actions = new Part(true);
            instances = new Part(true);
            return;
        }

        actions = new Part(parts[1]);

        if (parts.length < 3) {
            instances = new Part(true);
            return;
        }

        instances = new Part(parts[2]);

        if (parts.length > 3) {
            description = parts[3];
        }

        if (wildcard && actions.isWildcard() && instances.isWildcard()) fullWildcard = true;
    }

    public boolean isFullWildcard() {
        return fullWildcard;
    }

    public boolean isWildcard() {
        return wildcard;
    }

    public String getObjectClass() {
        return clazz;
    }

    public Part getActions() {
        return actions;
    }

    public String getDescription() {
        return description;
    }

    public Part getObjectInstances() {
        return instances;
    }

    @Override
    public String getAuthority() {
        return ResourceAceVoter.PREFIX_LOWER + toString();
    }

    public String toString() {
        if (isFullWildcard()) return MSecurity.WILDCARD_TOKEN;
        return clazz
                + MSecurity.PART_DIVIDER_TOKEN
                + actions
                + MSecurity.PART_DIVIDER_TOKEN
                + instances
                + MSecurity.PART_DIVIDER_TOKEN
                + description;
    }
}
