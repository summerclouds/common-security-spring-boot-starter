package org.summerclouds.common.security.realm;

import java.util.HashMap;

import org.summerclouds.common.security.permissions.Acl;

public class MemoryRoleAclRealm implements RoleAclRealm {

	private HashMap<String, Acl> acls = new HashMap<>();
	
	@Override
	public Acl getAclforRole(String rolename) {
		Acl acl = acls.get(rolename);
		return acl;
	}

	public MemoryRoleAclRealm add(String rolename, String ... aces) {
		Acl acl = new Acl(aces);
		acls.put(rolename, acl);
		return this;
	}

	@Override
	public boolean isEnabled() {
		return !acls.isEmpty();
	}

}
