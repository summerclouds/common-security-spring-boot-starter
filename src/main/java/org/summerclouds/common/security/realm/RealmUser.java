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

import java.util.Collection;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.summerclouds.common.security.basicauth.RemotePasswordValidation;

public class RealmUser extends User implements RemotePasswordValidation {

    private static final long serialVersionUID = 1L;
    private Realm realm;
    private boolean doNotEraseCredentials = false;

    public RealmUser(
            Realm realm,
            String username,
            String password,
            boolean enabled,
            boolean accountNonExpired,
            boolean credentialsNonExpired,
            boolean accountNonLocked,
            Collection<? extends GrantedAuthority> authorities) {
        super(
                username,
                password,
                enabled,
                accountNonExpired,
                credentialsNonExpired,
                accountNonLocked,
                authorities);
        this.realm = realm;
    }

    public RealmUser(
            Realm realm,
            String username,
            String password,
            Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.realm = realm;
    }

    public Realm getRealm() {
        return realm;
    }

    @Override
    public boolean validatePassword(String presentedPassword, MessageSourceAccessor messages)
            throws AuthenticationException {
        if (getRealm() instanceof PasswordValidationRealm) {
            ((PasswordValidationRealm) getRealm())
                    .validatePassword(this, presentedPassword, messages);
            return true;
        }
        return false;
    }

    @Override
    public void eraseCredentials() {
        if (!doNotEraseCredentials) super.eraseCredentials();
    }

    public boolean isDoNotEraseCredentials() {
        return doNotEraseCredentials;
    }

    public void setDoNotEraseCredentials(boolean doNotEraseCredentials) {
        this.doNotEraseCredentials = doNotEraseCredentials;
    }
}
