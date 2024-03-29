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

public interface Role {

    /**
     * Returns the rolename used to assign the role to the user. Cannot return <code>null</code>.
     *
     * @return the rolename (never <code>null</code>)
     */
    String getRolename();

    /**
     * Indicates whether the role is enabled or disabled. A disabled role will be ignored.
     *
     * @return <code>true</code> if the user is enabled, <code>false</code> otherwise
     */
    boolean isEnabled();

    /**
     * Indicates whether the role is locked or unlocked. A user in a locked role cannot be
     * authenticated.
     *
     * @return <code>true</code> if the user is not locked, <code>false</code> otherwise
     */
    boolean isAccountNonLocked();
}
