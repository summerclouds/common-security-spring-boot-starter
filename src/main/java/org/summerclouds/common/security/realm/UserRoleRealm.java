package org.summerclouds.common.security.realm;

import java.util.Set;

public interface UserRoleRealm extends Realm {

	Set<String> getRolesForUser(String username);

}
