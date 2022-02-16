package org.summerclouds.common.security.realm;

import org.springframework.security.core.userdetails.User;

public interface UserRealm extends Realm {

	/**
	 * Search for the user and return the user object. If the user is not found
	 * return null.
	 * 
	 * @param username
	 * @return The user or null
	 */
	User getUser(String username);

}
