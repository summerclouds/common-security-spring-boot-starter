package org.summerclouds.common.security.realm;

import java.util.HashMap;

import org.summerclouds.common.security.permissions.PermSet;

public class MemoryRoleAclRealm implements RoleAclRealm {

	private HashMap<String, PermSet> acls = new HashMap<>();
	
	@Override
	public PermSet getAclforRole(String rolename) {
		PermSet acl = acls.get(rolename);
		return acl;
	}

	public MemoryRoleAclRealm add(String rolename, String ... aces) {
		PermSet acl = new PermSet(aces);
		acls.put(rolename, acl);
		return this;
	}

	@Override
	public boolean isEnabled() {
		return !acls.isEmpty();
	}

}
