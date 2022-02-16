package org.summerclouds.common.security.realm;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.userdetails.User;

public interface PasswordValidationRealm {

	void validatePassword(User realmUser, String presentedPassword, MessageSourceAccessor messages);

}
