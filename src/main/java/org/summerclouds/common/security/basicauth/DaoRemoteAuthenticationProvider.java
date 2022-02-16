package org.summerclouds.common.security.basicauth;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

public class DaoRemoteAuthenticationProvider extends DaoAuthenticationProvider {

	@Override
	protected void additionalAuthenticationChecks(UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {

		if (userDetails instanceof RemotePasswordValidation) {
			String presentedPassword = authentication.getCredentials().toString();
			if ( !((RemotePasswordValidation)userDetails).validatePassword(presentedPassword, this.messages))
				super.additionalAuthenticationChecks(userDetails, authentication);
		} else {
			logger.info("user can't validate password by remote, fallback to default");
			super.additionalAuthenticationChecks(userDetails, authentication);
		}
	}

}
