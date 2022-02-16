package org.summerclouds.common.security.realm;

import org.summerclouds.common.security.permissions.Acl;

public interface UserAclRealm extends Realm {

	/**
	 * Return a set of ACEs for the given user.
	 * 
	 * @param username
	 * @return
	 */
	Acl getAclForUser(String username);

}
