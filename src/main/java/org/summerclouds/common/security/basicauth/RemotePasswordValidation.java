package org.summerclouds.common.security.basicauth;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.AuthenticationException;

public interface RemotePasswordValidation {

	/**
	 * Validate the password and throw an exception if authentication failed.
	 * This interface will be used by DaoRemoteAuthenticationProvider and delegated
	 * to the user object. Return false if the user can't authenticate remote in this
	 * case the default authentication via credentials will be used. 
	 * 
	 * @param presentedPassword The given password
	 * @param messages The current message source accessor
	 * @return true if authentication was successful or false if not supported
	 * @throws AuthenticationException If authentication was not successful
	 */
	boolean validatePassword(String presentedPassword, MessageSourceAccessor messages) throws AuthenticationException;

}
