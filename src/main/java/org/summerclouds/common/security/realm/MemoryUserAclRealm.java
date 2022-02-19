package org.summerclouds.common.security.realm;

import java.util.HashMap;

import org.summerclouds.common.security.permissions.PermSet;

public class MemoryUserAclRealm implements UserAclRealm {

	private HashMap<String, PermSet> acls = new HashMap<>();
	
	@Override
	public PermSet getAclForUser(String username) {
		PermSet acl = acls.get(username);
		return acl;
	}

	public MemoryUserAclRealm add(String username, String ... aces) {
		PermSet acl = new PermSet(aces);
		acls.put(username, acl);
		return this;
	}

	@Override
	public boolean isEnabled() {
		return !acls.isEmpty();
	}
	
	
}
