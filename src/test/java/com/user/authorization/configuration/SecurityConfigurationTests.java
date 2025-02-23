package com.user.authorization.configuration;


import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import static org.hamcrest.CoreMatchers.is;

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
        mockMvc.perform(post(GET_ACCESS_TOKEN_ENDPOINT).param("client_id", "client-1")
                        .param("client_secret", "secret")
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andDo(print())
                .andExpect(jsonPath("$.token_type", is("Bearer")))
                .andExpect(jsonPath("$.access_token").isString());
    }
}
