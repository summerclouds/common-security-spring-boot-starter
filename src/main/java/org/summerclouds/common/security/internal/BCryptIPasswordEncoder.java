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
package org.summerclouds.common.security.internal;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.summerclouds.common.core.crypt.IPasswordEncoder;
import org.summerclouds.common.core.error.NotSupportedException;

public class BCryptIPasswordEncoder implements IPasswordEncoder {

    private PasswordEncoder encoder = new BCryptPasswordEncoder();

    @Override
    public String encode(String plain, String secret) {
        return encoder.encode(plain);
    }

    @Override
    public String decode(String encoded, String secret) {
        throw new NotSupportedException("decode not supported for bcrypt");
    }

    @Override
    public boolean validate(String plain, String encoded, String secret) {
        return encoder.matches(plain, encoded);
    }
}
