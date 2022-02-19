package org.summerclouds.common.security.jwt;

import java.util.Collection;
import java.util.Date;
import java.util.function.Function;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.summerclouds.common.core.log.Log;
import org.summerclouds.common.core.tool.MSystem;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;
	private static Log log = Log.getLog(JwtAuthenticationToken.class);
	private String secret = "abc123";
	private Claims claims;
	private String token;
	private String username;
	
    public JwtAuthenticationToken(String token) {
    	super(null);
        this.token = token;
        try {
	        claims = Jwts.parser()
	        .setSigningKey(secret)
	        .parseClaimsJws(token)
	        .getBody();
	        
	        username = getUsernameFromToken();
	        
        } catch (Throwable t) {
        	log.d("parse jwt token failed",token);
        }
        setAuthenticated(false);
    }
    
    public JwtAuthenticationToken(String token, Claims claims, Collection<? extends GrantedAuthority> authorities) {
    	super(authorities);
    	MSystem.acceptCaller(AbstractJwtAuthenticationProvider.class, DaoJwtAuthenticationProvider.class);
        this.token = token;
        this.claims = claims;
        setAuthenticated(true);
    }

    public boolean isTokenNotExpired() {
    	if (!isTokenValid()) return true;
        final Date expiration = getExpirationDateFromToken();
        return expiration.after(new Date());
    }

    public Date getExpirationDateFromToken() {
    	if (!isTokenValid()) return null;
        return getClaimFromToken(Claims::getExpiration);
    }

    public <T> T getClaimFromToken(Function<Claims, T> claimsResolver) {
    	if (!isTokenValid()) return null;
        return claimsResolver.apply(claims);
    }

    public String getUsernameFromToken() {
    	if (!isTokenValid()) return null;
        return getClaimFromToken(Claims::getSubject);
    }

	/**
	 * Returns true if the token can be read also if token is expired.
	 * @return
	 */
	public boolean isTokenValid() {
		return claims != null;
	}

	@Override
	public Object getCredentials() {
		return token;
	}

	@Override
	public Object getPrincipal() {
		return username;
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.token = null;
		this.claims = null;
	}
	
	public Claims getClaims() {
		return claims;
	}

	public String getToken() {
		return token;
	}

}
