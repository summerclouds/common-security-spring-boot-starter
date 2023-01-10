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
package org.summerclouds.common.security.jwt;

public class TokenResponse {

    private String username;
    private long timeout;
    private String token;

    public TokenResponse(String username, long timeout, String token) {
        this.username = username;
        this.timeout = timeout;
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public long getTimeout() {
        return timeout;
    }

    public String getToken() {
        return token;
    }
}
