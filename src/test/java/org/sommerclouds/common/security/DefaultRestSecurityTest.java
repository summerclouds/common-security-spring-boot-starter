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

@WebMvcTest(
        controllers = {
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
        })
public class DefaultRestSecurityTest extends TestCase {

    @Autowired private MockMvc mockMvc;

    //	@Test
    //	public void testError400() throws Exception {
    //		this.mockMvc.perform(get("/error400").headers(getBasicAuth("username",
    // "password"))).andDo(print()).andExpect(status().isOk())
    //		.andExpect(jsonPath("$.content").value("Hello, World!"));
    //	}

    @Test
    public void testRequest() throws Exception {
        this.mockMvc
                .perform(get("/hello").headers(getBasicAuth("username", "password")))
                .andDo(print())
                .andExpect(status().isOk())
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
