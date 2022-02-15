package org.summerclouds.common.security.permissions;

import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.summerclouds.common.core.tool.MString;

public class AcePartSet implements Iterable<String> {

    private boolean wildcard = false;
    private Set<String> content = new TreeSet<>();

    public AcePartSet(boolean wildcard) {
    	this.wildcard = wildcard;
    	if (wildcard)
    		this.content.add(WildcadAce.WILDCARD_TOKEN);
    }
	
    public AcePartSet(String content) {
    	content = content.trim();
    	if (content.equals( WildcadAce.WILDCARD_TOKEN)) {
    		wildcard = true;
    		this.content.add(WildcadAce.WILDCARD_TOKEN);
    		return;
    	}
    	
    	String[] parts = content.split(WildcadAce.SUBPART_DIVIDER_TOKEN);
    	for (String part : parts) {
    		part = part.trim();
    		if (part.length() > 0) {
    			if (part.equals(WildcadAce.WILDCARD_TOKEN)) {
    				wildcard = true;
    				this.content.clear();
    				this.content.add(WildcadAce.WILDCARD_TOKEN);
    				return;
    			}
    			this.content.add(part);
    		}
    	}
    	
    }
    
    public boolean isWildcard() {
    	return wildcard;
    }

	@Override
	public Iterator<String> iterator() {
		return content.iterator();
	}

	public boolean contains(String str) {
		return content.contains(str);
	}

	public String toString() {
		return MString.join(iterator(), WildcadAce.SUBPART_DIVIDER_TOKEN);
	}

}
