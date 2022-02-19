package org.summerclouds.common.security.realm;

import org.summerclouds.common.security.permissions.PermSet;

public interface UserAclRealm extends Realm {

	/**
	 * Return a set of ACEs for the given user.
	 * 
	 * @param username
	 * @return
	 */
	PermSet getAclForUser(String username);

}
