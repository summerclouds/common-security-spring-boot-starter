package org.summerclouds.common.security.realm;

public interface UserDataRealm extends Realm {

	UserData getUserData(String username);
}
