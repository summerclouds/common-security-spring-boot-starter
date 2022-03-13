package org.summerclouds.common.security.realm;

import java.util.Collection;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.summerclouds.common.security.basicauth.RemotePasswordValidation;

public class RealmUser extends User implements RemotePasswordValidation {

	private static final long serialVersionUID = 1L;
	private Realm realm;
	private boolean doNotEraseCredentials = false;

	public RealmUser(Realm realm, String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
		this.realm = realm;
	}

	public RealmUser(Realm realm, String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
		this.realm = realm;
	}
	
	public Realm getRealm() {
		return realm;
	}

	@Override
	public boolean validatePassword(String presentedPassword, MessageSourceAccessor messages) throws AuthenticationException {
		if (getRealm() instanceof PasswordValidationRealm) {
			((PasswordValidationRealm)getRealm()).validatePassword(this, presentedPassword, messages);
			return true;
		} 
		return false;
	}

	@Override
	public void eraseCredentials() {
		if (!doNotEraseCredentials)
			super.eraseCredentials();
	}

	public boolean isDoNotEraseCredentials() {
		return doNotEraseCredentials;
	}

	public void setDoNotEraseCredentials(boolean doNotEraseCredentials) {
		this.doNotEraseCredentials = doNotEraseCredentials;
	}

}
