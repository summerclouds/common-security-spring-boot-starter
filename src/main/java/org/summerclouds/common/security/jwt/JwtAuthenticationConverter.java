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

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.summerclouds.common.core.cfg.CfgBoolean;
import org.summerclouds.common.core.cfg.CfgString;

public class JwtAuthenticationConverter implements AuthenticationConverter {

    public static final String AUTHENTICATION_SCHEME_BEARER = "Bearer ";
    public static CfgString CFG_ALTERNATIVE_PARAMETER =
            new CfgString(JwtAuthenticationConverter.class, "alternativeParameter", "_jwt_token");
    public static CfgBoolean CFG_ALTERNATIVE_ENABLED =
            new CfgBoolean(JwtAuthenticationConverter.class, "alternativeEnabled", false);

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    public JwtAuthenticationConverter() {
        this(new WebAuthenticationDetailsSource());
    }

    public JwtAuthenticationConverter(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
        return this.authenticationDetailsSource;
    }

    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    @Override
    public JwtAuthenticationToken convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        String token = null;
        if (header != null) {
            header = header.trim();
            if (StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BEARER)) {
                token = header.substring(AUTHENTICATION_SCHEME_BEARER.length());
            }
        }
        if (token == null && CFG_ALTERNATIVE_ENABLED.value())
            token = request.getParameter(CFG_ALTERNATIVE_PARAMETER.value());
        if (token == null) return null;

        JwtAuthenticationToken result = new JwtAuthenticationToken(token);
        result.setDetails(this.authenticationDetailsSource.buildDetails(request));
        return result;
    }
}
