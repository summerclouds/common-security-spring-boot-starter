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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class JwtConfigurer<B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<JwtConfigurer<B>, B> {

    private AuthenticationEntryPoint authenticationEntryPoint = new BasicAuthenticationEntryPoint();

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    private static final String DEFAULT_REALM = "Realm";

    public JwtConfigurer() {
        ((BasicAuthenticationEntryPoint) authenticationEntryPoint).setRealmName(DEFAULT_REALM);
    }

    @Override
    public void configure(B http) {
        AuthenticationManager authenticationManager =
                http.getSharedObject(AuthenticationManager.class);
        JwtAuthenticationFilter jwtAuthenticationFilter =
                new JwtAuthenticationFilter(authenticationManager, this.authenticationEntryPoint);
        if (this.authenticationDetailsSource != null) {
            jwtAuthenticationFilter.setAuthenticationDetailsSource(
                    this.authenticationDetailsSource);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            jwtAuthenticationFilter.setRememberMeServices(rememberMeServices);
        }
        jwtAuthenticationFilter = postProcess(jwtAuthenticationFilter);
        http.addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class);
    }

    public JwtConfigurer<B> authenticationEntryPoint(
            AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    public JwtConfigurer<B> authenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return this;
    }

    public JwtConfigurer<B> realmName(String realmName) {
        if (authenticationEntryPoint != null
                && authenticationEntryPoint instanceof BasicAuthenticationEntryPoint) {
            ((BasicAuthenticationEntryPoint) authenticationEntryPoint).setRealmName(DEFAULT_REALM);
            ((BasicAuthenticationEntryPoint) authenticationEntryPoint).afterPropertiesSet();
        }
        return this;
    }
}
