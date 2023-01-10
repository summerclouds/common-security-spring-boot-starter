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

import org.summerclouds.common.core.tool.MSecurity;

/**
 * Format: object:action:intance:description
 *
 * @author mikehummel
 */
public class Ace {

    private String clazz;

    private String action;

    private String instance;

    private String description = "";

    public Ace(String clazz, String action, String instance) {
        this.clazz = clazz == null ? MSecurity.WILDCARD_TOKEN : normalize(clazz);
        this.action = action == null ? MSecurity.WILDCARD_TOKEN : normalize(action);
        this.instance = instance == null ? MSecurity.WILDCARD_TOKEN : normalize(instance);
    }

    public Ace(String perm) {

        String[] parts = perm.split(MSecurity.PART_DIVIDER_TOKEN, 4);
        String clazz = null;
        String action = null;
        String instance = null;
        if (parts.length > 0) {
            clazz = parts[0];
            if (parts.length > 1) {
                action = parts[1];
                if (parts.length > 2) {
                    instance = parts[2];
                    if (parts.length > 3) description = parts[3];
                }
            }
        }

        this.clazz = clazz == null ? MSecurity.WILDCARD_TOKEN : normalize(clazz);
        this.action = action == null ? MSecurity.WILDCARD_TOKEN : normalize(action);
        this.instance = instance == null ? MSecurity.WILDCARD_TOKEN : normalize(instance);
    }

    public static String normalize(String str) {
        if (str.indexOf(MSecurity.PART_DIVIDER_TOKEN) > -1)
            str = str.replace(MSecurity.PART_DIVIDER_TOKEN, "_");
        str = str.trim().toLowerCase();
        return str;
    }

    public String getObjectClass() {
        return clazz;
    }

    public String getAction() {
        return action;
    }

    public String getInstance() {
        return instance;
    }

    public String toString() {
        return clazz
                + MSecurity.PART_DIVIDER_TOKEN
                + action
                + MSecurity.PART_DIVIDER_TOKEN
                + instance
                + MSecurity.PART_DIVIDER_TOKEN
                + description;
    }

    public static String normalize(String clazz, String action, String instance) {
        return normalize(clazz)
                + MSecurity.PART_DIVIDER_TOKEN
                + normalize(action)
                + MSecurity.PART_DIVIDER_TOKEN
                + normalize(instance);
    }
}
