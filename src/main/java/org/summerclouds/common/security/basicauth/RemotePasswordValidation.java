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
package org.summerclouds.common.security.basicauth;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.AuthenticationException;

public interface RemotePasswordValidation {

    /**
     * Validate the password and throw an exception if authentication failed. This interface will be
     * used by DaoRemoteAuthenticationProvider and delegated to the user object. Return false if the
     * user can't authenticate remote in this case the default authentication via credentials will
     * be used.
     *
     * @param presentedPassword The given password
     * @param messages The current message source accessor
     * @return true if authentication was successful or false if not supported
     * @throws AuthenticationException If authentication was not successful
     */
    boolean validatePassword(String presentedPassword, MessageSourceAccessor messages)
            throws AuthenticationException;
}
