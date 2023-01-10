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

import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.summerclouds.common.core.tool.MCollection;
import org.summerclouds.common.core.tool.MSecurity;
import org.summerclouds.common.core.tool.MString;

public class Part implements Iterable<String>, Comparable<Part> {

    private boolean wildcard = false;
    private Set<String> content = new TreeSet<>();

    public Part(boolean wildcard) {
        this.wildcard = wildcard;
        if (wildcard) this.content.add(MSecurity.WILDCARD_TOKEN);
    }

    public Part(String content) {
        content = content.trim();
        if (content.equals(MSecurity.WILDCARD_TOKEN)) {
            wildcard = true;
            this.content.add(MSecurity.WILDCARD_TOKEN);
            return;
        }

        String[] parts = content.split(MSecurity.SUBPART_DIVIDER_TOKEN);
        for (String part : parts) {
            part = part.trim();
            if (part.length() > 0) {
                if (part.equals(MSecurity.WILDCARD_TOKEN)) {
                    wildcard = true;
                    this.content.clear();
                    this.content.add(MSecurity.WILDCARD_TOKEN);
                    return;
                }
                this.content.add(part);
            }
        }
    }

    public boolean isWildcard() {
        return wildcard;
    }

    @Override
    public Iterator<String> iterator() {
        return content.iterator();
    }

    public boolean contains(String str) {
        return content.contains(str);
    }

    public String toString() {
        return MString.join(iterator(), MSecurity.SUBPART_DIVIDER_TOKEN);
    }

    @Override
    public int compareTo(Part o) {
        return MCollection.compare(this.content, o.content);
    }
}
