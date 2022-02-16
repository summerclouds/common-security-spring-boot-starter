package org.summerclouds.common.security.realm;

import org.summerclouds.common.security.permissions.Acl;

public interface RoleAclRealm extends Realm {

	Acl getAclforRole(String rolename);

}
