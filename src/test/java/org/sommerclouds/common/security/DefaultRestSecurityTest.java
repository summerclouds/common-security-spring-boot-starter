package org.sommerclouds.common.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.summerclouds.common.core.internal.SpringSummerCloudsCoreAutoConfiguration;
import org.summerclouds.common.core.tool.MHttp;
import org.summerclouds.common.junit.TestCase;
import org.summerclouds.common.security.DefaultRestWebSecurityConfiguration;
import org.summerclouds.common.security.internal.SpringSummerCloudsSecurityAutoConfiguration;
import org.summerclouds.common.security.realm.RealmManager;

@WebMvcTest(controllers = {
				RealmManager.class, 
				HelloController.class,
				DefaultRestWebSecurityConfiguration.class,
				SpringSummerCloudsCoreAutoConfiguration.class,
				SpringSummerCloudsSecurityAutoConfiguration.class
		},
		properties = {
				"org.summerclouds.security.default.enabled=true",
				"spring.security.user.name = username",
				"spring.security.user.password = password"
		}
		)
public class DefaultRestSecurityTest extends TestCase {

	@Autowired
	private MockMvc mockMvc;

//	@Test
//	public void testError400() throws Exception {
//		this.mockMvc.perform(get("/error400").headers(getBasicAuth("username", "password"))).andDo(print()).andExpect(status().isOk())
//		.andExpect(jsonPath("$.content").value("Hello, World!"));
//	}

	@Test
	public void testRequest() throws Exception {
		this.mockMvc.perform(get("/hello").headers(getBasicAuth("username", "password"))).andDo(print()).andExpect(status().isOk())
		.andExpect(jsonPath("$.content").value("Hello, World!"));
	}

	@Test
	public void testRequestWithoutAuth() throws Exception {
		this.mockMvc.perform(get("/hello")).andDo(print()).andExpect(status().is(401));
	}
	
	public HttpHeaders getBasicAuth(String user, String passwd) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(MHttp.HEADER_AUTHORIZATION, MHttp.toBasicAuthorization(user, passwd));
		return headers;
	}

}
