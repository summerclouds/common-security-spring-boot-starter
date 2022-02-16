package org.summerclouds.common.security.permissions;

import java.util.Iterator;
import java.util.Set;
import java.util.TreeSet;

import org.summerclouds.common.core.tool.MCollection;
import org.summerclouds.common.core.tool.MString;

public class AcePartSet implements Iterable<String>, Comparable<AcePartSet> {

    private boolean wildcard = false;
    private Set<String> content = new TreeSet<>();

    public AcePartSet(boolean wildcard) {
    	this.wildcard = wildcard;
    	if (wildcard)
    		this.content.add(WildcardAce.WILDCARD_TOKEN);
    }
	
    public AcePartSet(String content) {
    	content = content.trim();
    	if (content.equals( WildcardAce.WILDCARD_TOKEN)) {
    		wildcard = true;
    		this.content.add(WildcardAce.WILDCARD_TOKEN);
    		return;
    	}
    	
    	String[] parts = content.split(WildcardAce.SUBPART_DIVIDER_TOKEN);
    	for (String part : parts) {
    		part = part.trim();
    		if (part.length() > 0) {
    			if (part.equals(WildcardAce.WILDCARD_TOKEN)) {
    				wildcard = true;
    				this.content.clear();
    				this.content.add(WildcardAce.WILDCARD_TOKEN);
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
		return MString.join(iterator(), WildcardAce.SUBPART_DIVIDER_TOKEN);
	}

	@Override
	public int compareTo(AcePartSet o) {
		return MCollection.compare(this.content, o.content);
	}

}
