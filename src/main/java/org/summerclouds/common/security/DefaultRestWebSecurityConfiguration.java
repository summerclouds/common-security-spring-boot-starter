package org.summerclouds.common.security;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.access.expression.WebExpressionVoter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.summerclouds.common.core.tool.MSpring;
import org.summerclouds.common.core.tool.MString;
import org.summerclouds.common.security.jwt.DaoJwtAuthenticationProvider;
import org.summerclouds.common.security.jwt.JwtConfigurer;
import org.summerclouds.common.security.permissions.PermSet;
import org.summerclouds.common.security.permissions.ResourceAceVoter;
import org.summerclouds.common.security.permissions.RoleAceVoter;
import org.summerclouds.common.security.realm.RealmManager;

@Configuration
@EnableWebSecurity
@ConditionalOnProperty(name="org.summerclouds.security.default.enabled",havingValue="true")
public class DefaultRestWebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(realmManager());
        auth.authenticationProvider(new DaoJwtAuthenticationProvider(auth.getDefaultUserDetailsService()));
    }

	@Bean
	RealmManager realmManager() {
		return new RealmManager();
	}

    @Override
    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().mvcMatchers("/hello");
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {

		ArrayList<GrantedAuthority> guestAuth = new ArrayList<>();
		String permStr = MSpring.getValue("spring.security.guest.permissions");
    	if (permStr != null)
    		guestAuth.add(new PermSet(permStr));
		String authStr = MSpring.getValue("spring.security.guest.authorities");
		if (authStr != null)
			for (String a : authStr.split(","))
				if (MString.isSetTrim(a))
					guestAuth.add(new SimpleGrantedAuthority(a));
		if (guestAuth.size() == 0) // add dummy auth
			guestAuth.add(new SimpleGrantedAuthority(UUID.randomUUID().toString()));
		
    	http.csrf().disable()
        .formLogin().disable()
        .logout().disable()
//        .anonymous().principal("guest").authorities(guestAuth)
//        .and()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers("/**").hasAuthority("ace_web:${method}:${url}")
        .accessDecisionManager(accessDecisionManager())
        .and()
        .apply(new JwtConfigurer<>())
        .and()
          .httpBasic()
          ;    

    }

//		http.authorizeRequests()
//	      .anyRequest().authenticated()
//	      .and().httpBasic();

//	    .anyRequest()
//	    .authenticated()
//	    .accessDecisionManager(accessDecisionManager());

	public void addCorsMappings(CorsRegistry registry) {
		registry
		.addMapping("/**")
		.allowedMethods("GET", "POST", "PUT", "DELETE")
		.allowedOrigins("*")
		.allowedHeaders("*");
	}

	@Bean
	public AccessDecisionManager accessDecisionManager() {
		
	    List<AccessDecisionVoter<? extends Object>> decisionVoters 
	      = Arrays.asList(
  		    new ResourceAceVoter(),
	        new WebExpressionVoter(),
	        new RoleAceVoter(), // instead of RoleVoter()
	        new AuthenticatedVoter()
	        );
	    return new AffirmativeBased(decisionVoters);
	}
	    
}
