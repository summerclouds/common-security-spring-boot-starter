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

public class Perm implements GrantedAuthority, Serializable {

	private static final long serialVersionUID = 1L;

	private static final String WILDCARD2 = Ace.WILDCARD_TOKEN + Ace.PART_DIVIDER_TOKEN + Ace.WILDCARD_TOKEN;
	private static final String WILDCARD3 = Ace.WILDCARD_TOKEN + Ace.PART_DIVIDER_TOKEN + Ace.WILDCARD_TOKEN + Ace.PART_DIVIDER_TOKEN + Ace.WILDCARD_TOKEN;

    private String object; 
    private boolean fullWildcard = false;
    private boolean wildcard = false;
    
    private Part actions; // action list
    
    private Part instances; // instance list

	private String description = "";
    
    public Perm(String wildcardString) {
    	Assert.notNull(wildcardString, "wildcard string can't be null");
    	// parse
    	wildcardString = wildcardString.trim().toLowerCase();
    	Assert.hasText(wildcardString, "wildcard string must be set");
    	if (wildcardString.equals(Ace.WILDCARD_TOKEN) || wildcardString.equals(WILDCARD2) || wildcardString.equals(WILDCARD3)) {
    		object = Ace.WILDCARD_TOKEN;
    		actions = new Part(true);
    		instances = new Part(true);
    		fullWildcard = true;
    		wildcard = true;
    		return;
    	}
    	
    	String[] parts = wildcardString.split(Ace.PART_DIVIDER_TOKEN,4);
    	Assert.isTrue(parts.length > 0, "minimum object name"); // paranoia
    	
    	object = parts[0].trim();
    	wildcard = object.equals(Ace.WILDCARD_TOKEN);
    	
    	if (parts.length < 2) {
    		actions = new Part(true);
    		instances = new Part(true);
    		return;
    	}
    	
    	actions = new Part(parts[1]);
    	
    	if (parts.length < 3) {
    		instances = new Part(true);
    		return;
    	}
    	
    	instances = new Part(parts[2]);
    	
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
    
    public Part getActions() {
    	return actions;
    }
    
    public String getDescription() {
    	return description;
    }

    public Part getInstances() {
    	return instances;
    }

	@Override
	public String getAuthority() {
		return ResourceAceVoter.PREFIX_LOWER + toString();
	}
	
	public String toString() {
		if (isFullWildcard())
			return Ace.WILDCARD_TOKEN;
		return object + Ace.PART_DIVIDER_TOKEN + actions + Ace.PART_DIVIDER_TOKEN + instances + Ace.PART_DIVIDER_TOKEN + description;
	}

}
