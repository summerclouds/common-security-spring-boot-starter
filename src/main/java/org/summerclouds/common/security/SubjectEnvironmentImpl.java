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
package org.summerclouds.common.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.summerclouds.common.core.security.ISubject;
import org.summerclouds.common.core.security.ISubjectEnvironment;

public class SubjectEnvironmentImpl implements ISubjectEnvironment {

    private Authentication previous;
    private SubjectImpl subject;

    public SubjectEnvironmentImpl(Authentication auth) {
        previous = SecurityContextHolder.getContext().getAuthentication();
        SecurityContextHolder.getContext().setAuthentication(auth);
        Object user = auth.getPrincipal();
        subject = new SubjectImpl((User) user, auth);
    }

    @Override
    public ISubject getSubject() {
        return subject;
    }

    @Override
    public void close() {
        SecurityContextHolder.getContext().setAuthentication(previous);
    }
}
