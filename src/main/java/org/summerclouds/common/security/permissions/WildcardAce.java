/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.summerclouds.common.security.permissions;

import java.io.Serializable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

public class WildcardAce implements GrantedAuthority, Serializable {

	private static final long serialVersionUID = 1L;

    protected static final String WILDCARD_TOKEN = "*";
    protected static final String PART_DIVIDER_TOKEN = ":";
    protected static final String SUBPART_DIVIDER_TOKEN = ",";

    private String object; 
    private boolean fullWildcard = false;
    private boolean wildcard = false;
    
    private AcePartSet actions; // action list
    
    private AcePartSet instances; // instance list

	private String description = "";
    
    public WildcardAce(String wildcardString) {
    	Assert.notNull(wildcardString, "wildcard string can't be null");
    	// parse
    	wildcardString = wildcardString.trim().toLowerCase();
    	Assert.hasText(wildcardString, "wildcard string must be set");
    	if (wildcardString.equals(WILDCARD_TOKEN)) {
    		object = WILDCARD_TOKEN;
    		actions = new AcePartSet(true);
    		instances = new AcePartSet(true);
    		fullWildcard = true;
    		wildcard = true;
    		return;
    	}
    	
    	String[] parts = wildcardString.split(PART_DIVIDER_TOKEN,4);
    	Assert.isTrue(parts.length > 0, "minimum object name"); // paranoia
    	
    	object = parts[0].trim();
    	wildcard = object.equals(WILDCARD_TOKEN);
    	
    	if (parts.length < 2) {
    		actions = new AcePartSet(true);
    		instances = new AcePartSet(true);
    		return;
    	}
    	
    	actions = new AcePartSet(parts[1]);
    	
    	if (parts.length < 3) {
    		instances = new AcePartSet(true);
    		return;
    	}
    	
    	instances = new AcePartSet(parts[2]);
    	
    	if (parts.length > 3) {
    		description  = parts[3];
    	}
    	
    	if (wildcard && actions.isWildcard() && instances.isWildcard())
    		fullWildcard = true;
    	
    }
    
    public boolean isFullWildcard() {
    	return fullWildcard;
    }
    
    public boolean isWildcard() {
    	return wildcard;
    }

    
    public String getObject() {
    	return object;
    }
    
    public AcePartSet getActions() {
    	return actions;
    }
    
    public String getDescription() {
    	return description;
    }

    public AcePartSet getInstances() {
    	return instances;
    }

	@Override
	public String getAuthority() {
		return ResourceAceVoter.PREFIX_LOWER + toString();
	}
	
	public String toString() {
		if (isFullWildcard())
			return WILDCARD_TOKEN;
		return object + PART_DIVIDER_TOKEN + actions + PART_DIVIDER_TOKEN + instances + PART_DIVIDER_TOKEN + description;
	}

}
