package org.summerclouds.common.security.realm;

public interface RoleRealm extends Realm {

	Role getRole(String rolename);

}
