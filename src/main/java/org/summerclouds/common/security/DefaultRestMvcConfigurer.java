package org.summerclouds.common.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@ConditionalOnProperty(name="org.summerclouds.security.default.enabled",havingValue="true")
public class DefaultRestMvcConfigurer implements WebMvcConfigurer {

	@Override
    public void addInterceptors(InterceptorRegistry registry) {
       registry.addInterceptor(new RestInterceptor()).addPathPatterns("/**");
    }
	
	
}
