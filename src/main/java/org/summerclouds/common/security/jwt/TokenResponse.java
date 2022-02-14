package org.summerclouds.common.security.jwt;

public class TokenResponse {

	private String username;
	private long timeout;
	private String token;

	public TokenResponse(String username, long timeout, String token) {
		this.username=username;
		this.timeout=timeout;
		this.token=token;
	}
	
	public String getUsername() {
		return username;
	}

	public long getTimeout() {
		return timeout;
	}

	public String getToken() {
		return token;
	}

}
