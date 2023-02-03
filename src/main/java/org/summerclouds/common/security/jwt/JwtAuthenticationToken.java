/**
 * Copyright (C) 2022 Mike Hummel (mh@mhus.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
            claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();

            username = getUsernameFromToken();

        } catch (Exception t) {
            log.d("parse jwt token failed", token);
        }
        setAuthenticated(false);
    }

    public JwtAuthenticationToken(
            String token, Claims claims, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        MSystem.acceptCaller(
                AbstractJwtAuthenticationProvider.class, DaoJwtAuthenticationProvider.class);
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
     *
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
