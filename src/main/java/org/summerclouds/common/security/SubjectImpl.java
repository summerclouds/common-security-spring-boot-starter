package org.summerclouds.common.security;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.summerclouds.common.core.security.ISubject;
import org.summerclouds.common.core.tool.MSecurity;
import org.summerclouds.common.core.tool.MSpring;
import org.summerclouds.common.core.tool.MSystem;
import org.summerclouds.common.core.util.SingleList;
import org.summerclouds.common.security.permissions.Ace;
import org.summerclouds.common.security.permissions.ResourceAceVoter;
import org.summerclouds.common.security.permissions.RoleAceVoter;

public class SubjectImpl implements ISubject {
	
	private User user;
	private Authentication authentication;

	public SubjectImpl(User user, Authentication authentication) {
		this.user = user;
		this.authentication = authentication;
	}
	
	@Override
	public String getName() {
		return user.getUsername();
	}

	@Override
	public Object getPrincipal() {
		return user;
	}
	
	public Authentication getAuthentication() {
		return authentication;
	}

	@Override
	public boolean hasRole(String role) {
		AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
		Collection<ConfigAttribute> list = new SingleList<>(new ConfigAttributeImpl( RoleAceVoter.ROLE_PREFIX + role));
		try {
			adm.decide(authentication, SecurityImpl.FILTER_INVOCATION, list);
			return true;
		} catch (AccessDeniedException e) {}
		return false;
	}

	@Override
	public boolean hasPermission(String ace) {
		AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
		Collection<ConfigAttribute> list = new SingleList<>(new ConfigAttributeImpl(ResourceAceVoter.PREFIX_UPPER + ace));
		try {
			adm.decide(authentication, SecurityImpl.FILTER_INVOCATION, list);
			return true;
		} catch (AccessDeniedException e) {}
		return false;
	}

	@Override
	public boolean hasPermission(String object, String action, String instance) {
		AccessDecisionManager adm = MSpring.lookup(AccessDecisionManager.class);
		Collection<ConfigAttribute> list = new SingleList<>(new ConfigAttributeImpl(ResourceAceVoter.PREFIX_UPPER + Ace.normalize(object,action,instance)));
		try {
			adm.decide(authentication, MSecurity.get(), list);
			return true;
		} catch (AccessDeniedException e) {}
		return false;
	}

	@Override
	public boolean hasPermission(ISubject subject, Class<?> object, String action, String instance) {
		return hasPermission(MSystem.getCanonicalClassName(object), action, instance);
	}

	public String toString() {
		return user.getUsername();
	}
}
