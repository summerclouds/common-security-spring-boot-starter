package org.summerclouds.common.security.realm;

import org.summerclouds.common.security.permissions.PermSet;

public interface RoleAclRealm extends Realm {

	PermSet getAclforRole(String rolename);

}
