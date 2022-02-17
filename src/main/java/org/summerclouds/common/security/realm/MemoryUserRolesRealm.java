package org.summerclouds.common.security.realm;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import org.summerclouds.common.core.tool.MCollection;

public class MemoryUserRolesRealm implements UserRoleRealm {

	private HashMap<String,Set<String>> roles = new HashMap<>();
	
	@Override
	public Set<String> getRolesForUser(String username) {
		return roles.get(username);
	}
	
	public MemoryUserRolesRealm add(String username, String ... roles) {
        Set<String> set = new HashSet<>();
        for (String item : roles)
        	set.add(item);
		this.roles.put(username, MCollection.toSet(roles));
		return this;
	}

	@Override
	public boolean isEnabled() {
		return !roles.isEmpty();
	}

}
