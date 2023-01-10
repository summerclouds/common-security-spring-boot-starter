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

import java.util.Collection;
import java.util.Locale;
import java.util.UUID;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterInvocation;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.summerclouds.common.core.log.MLog;
import org.summerclouds.common.core.security.ISecurity;
import org.summerclouds.common.core.security.ISubject;
import org.summerclouds.common.core.security.ISubjectEnvironment;
import org.summerclouds.common.core.tool.MSecurity;
import org.summerclouds.common.core.tool.MSpring;
import org.summerclouds.common.core.tool.MSystem;
import org.summerclouds.common.core.util.SingleList;
import org.summerclouds.common.security.permissions.Ace;
import org.summerclouds.common.security.permissions.ResourceAceVoter;
import org.summerclouds.common.security.permissions.RoleAceVoter;

public class SecurityService extends MLog implements ISecurity {

    private static final String ATTR_LOCALE = "locale";
    static final FilterInvocation FILTER_INVOCATION = new FilterInvocation("/", "GET");

    @Value("${security.admin.username:admin}")
    private String adminUsername = "admin";

    @Override
    public ISubject getCurrent() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) return null; // ??
        Object p = authentication.getPrincipal();
        return p instanceof User ? new SubjectImpl((User) p, authentication) : null;
    }

    @Override
    public void subjectCleanup() {
        SecurityContextHolder.getContext().setAuthentication(null);
    }

    @Override
    public ISubject getSubject(String username) {
        UserDetailsService userService = MSpring.lookup(UserDetailsService.class);
        UserDetails user = userService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        user, UUID.randomUUID().toString(), user.getAuthorities());
        return new SubjectImpl((User) user, auth);
    }

    @Override
    public ISubjectEnvironment asSubject(String username) {
        UserDetailsService userService = MSpring.lookup(UserDetailsService.class);
        UserDetails user = userService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        user, UUID.randomUUID().toString(), user.getAuthorities());
        return new SubjectEnvironmentImpl(auth);
    }

    @Override
    public ISubjectEnvironment asSubject(ISubject subject) {
        Authentication auth = ((SubjectImpl) subject).getAuthentication();
        return new SubjectEnvironmentImpl(auth);
    }

    @Override
    public String getAdminName() {
        return adminUsername;
    }

    @Override
    public boolean hasPermission(Class<?> clazz, String action, String instance) {
        return hasPermission(MSystem.getCanonicalClassName(clazz), action, instance);
    }

    @Override
    public boolean hasPermission(String ace) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
        Collection<ConfigAttribute> list =
                new SingleList<>(new ConfigAttributeImpl(ResourceAceVoter.PREFIX_UPPER + ace));
        try {
            adm.decide(authentication, FILTER_INVOCATION, list);
            return true;
        } catch (AccessDeniedException e) {
        }
        return false;
    }

    @Override
    public boolean hasPermission(String clazz, String action, String instance) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
        Collection<ConfigAttribute> list =
                new SingleList<>(
                        new ConfigAttributeImpl(
                                ResourceAceVoter.PREFIX_UPPER
                                        + Ace.normalize(clazz, action, instance)));
        try {
            adm.decide(authentication, FILTER_INVOCATION, list);
            return true;
        } catch (AccessDeniedException e) {
        }
        return false;
    }

    @Override
    public boolean hasPermission(ISubject subject, Class<?> clazz, String action, String instance) {
        return hasPermission(subject, MSystem.getCanonicalClassName(clazz), action, instance);
    }

    @Override
    public boolean hasPermission(ISubject subject, String ace) {
        Authentication authentication = ((SubjectImpl) subject).getAuthentication();
        AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
        Collection<ConfigAttribute> list = new SingleList<>(new ConfigAttributeImpl(ace));
        try {
            adm.decide(authentication, FILTER_INVOCATION, list);
            return true;
        } catch (AccessDeniedException e) {
        }
        return false;
    }

    @Override
    public boolean hasPermission(ISubject subject, String clazz, String action, String instance) {
        Authentication authentication = ((SubjectImpl) subject).getAuthentication();
        AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
        Collection<ConfigAttribute> list =
                new SingleList<>(
                        new ConfigAttributeImpl(
                                ResourceAceVoter.PREFIX_UPPER
                                        + Ace.normalize(clazz, action, instance)));
        try {
            adm.decide(authentication, FILTER_INVOCATION, list);
            return true;
        } catch (AccessDeniedException e) {
        }
        return false;
    }

    @Override
    public boolean hasRole(String role) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
        Collection<ConfigAttribute> list =
                new SingleList<>(new ConfigAttributeImpl(RoleAceVoter.ROLE_PREFIX + role));
        try {
            adm.decide(authentication, FILTER_INVOCATION, list);
            return true;
        } catch (AccessDeniedException e) {
        }
        return false;
    }

    @Override
    public boolean hasRole(ISubject subject, String role) {
        Authentication authentication = ((SubjectImpl) subject).getAuthentication();
        AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
        Collection<ConfigAttribute> list =
                new SingleList<>(new ConfigAttributeImpl(RoleAceVoter.ROLE_PREFIX + role));
        try {
            adm.decide(authentication, FILTER_INVOCATION, list);
            return true;
        } catch (AccessDeniedException e) {
        }
        return false;
    }

    @Override
    public boolean isAdmin() {
        return hasPermission(MSecurity.WILDCARD_TOKEN);
    }

    @Override
    public boolean isAdmin(ISubject subject) {
        return hasPermission(subject, MSecurity.WILDCARD_TOKEN);
    }

    @Override
    public boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) return false;
        return authentication.isAuthenticated();
    }

    @Override
    public void setLocale(Locale locale) {
        ServletRequestAttributes attr =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        attr.getRequest().getSession(true).setAttribute(ATTR_LOCALE, locale);
    }

    public Locale getLocale() {
        ServletRequestAttributes attr =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        HttpSession session = attr.getRequest().getSession(false);
        if (session != null) {
            Object locale = session.getAttribute(ATTR_LOCALE);
            if (locale != null) {
                if (locale instanceof Locale) return (Locale) locale;
                if (locale instanceof String) return Locale.forLanguageTag((String) locale);
            }
        }
        return Locale.getDefault();
    }

    @Override
    public Object getSessionAttribute(String key) {
        ServletRequestAttributes attr =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        if (attr == null) return null;
        HttpSession session = attr.getRequest().getSession(false);
        if (session == null) return null;
        return session.getAttribute(key);
    }

    @Override
    public Object getSessionAttribute(String key, Object def) {
        ServletRequestAttributes attr =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        if (attr == null) return def;
        HttpSession session = attr.getRequest().getSession(false);
        if (session == null) return def;
        Object value = session.getAttribute(key);
        if (value == null) return def;
        return value;
    }

    @Override
    public void setSessionAttribute(String key, Object value) {
        ServletRequestAttributes attr =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        if (attr == null) return;
        attr.getRequest().getSession(true).setAttribute(key, value);
    }

    @Override
    public void touch() {
        ServletRequestAttributes attr =
                (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        if (attr == null) return;
        HttpSession session = attr.getRequest().getSession(true);
        int maxInactiveInterval = session.getMaxInactiveInterval();
        int currentInactiveTime =
                (int) (System.currentTimeMillis() - session.getLastAccessedTime() / 1000);
        session.setMaxInactiveInterval(maxInactiveInterval + currentInactiveTime);
    }

    @Override
    public boolean hasPermission(Class<?> clazz) {
        if (clazz == null) return false;
        return hasPermission(Class.class, MSecurity.EXECUTE, MSystem.getCanonicalClassName(clazz));
    }
}
