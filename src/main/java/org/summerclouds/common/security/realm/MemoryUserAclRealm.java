package org.summerclouds.common.security.realm;

import java.util.HashMap;

import org.summerclouds.common.security.permissions.Acl;

public class MemoryUserAclRealm implements UserAclRealm {

	private HashMap<String, Acl> acls = new HashMap<>();
	
	@Override
	public Acl getAclForUser(String username) {
		Acl acl = acls.get(username);
		return acl;
	}

	public MemoryUserAclRealm add(String username, String ... aces) {
		Acl acl = new Acl(aces);
		acls.put(username, acl);
		return this;
	}

	@Override
	public boolean isEnabled() {
		return !acls.isEmpty();
	}
	
	
}
