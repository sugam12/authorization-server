package com.user.authorization.configuration;


import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

import static org.hamcrest.CoreMatchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
public class SecurityConfigurationTests {

    private static final String GET_ACCESS_TOKEN_ENDPOINT = "/oauth2/token";

    @Autowired
    MockMvc mockMvc;

    @Test
    void testGetAccessTokenFail() throws Exception {
        mockMvc.perform(post(GET_ACCESS_TOKEN_ENDPOINT).param("client_id", "client-2")
                        .param("client_secret", "secret")
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andDo(print())
                .andExpect(jsonPath("$.error", is("invalid_client")));
    }

    @Test
    void testGetAccessTokenPass() throws Exception {
        mockMvc.perform(post(GET_ACCESS_TOKEN_ENDPOINT).param("client_id", "root")
                        .param("client_secret", "secret")
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andDo(print())
                .andExpect(header().string("X-Frame-Options","SAMEORIGIN"))
                .andExpect(header().string("Content-Security-Policy","script-src 'self http://some-trusted-scrips.com; object-src http://some-trusted-plugin; report-uri /csp-report-endpoint/ '"))
                .andExpect(jsonPath("$.token_type", is("Bearer")))
                .andExpect(jsonPath("$.access_token").isString());
    }
}
