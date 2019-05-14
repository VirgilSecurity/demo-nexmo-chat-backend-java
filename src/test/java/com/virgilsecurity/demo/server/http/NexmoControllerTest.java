/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.demo.server.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.virgilsecurity.demo.server.model.request.AuthRequest;
import com.virgilsecurity.demo.server.model.request.CreateUserRequest;
import com.virgilsecurity.demo.server.model.response.AuthResponse;
import com.virgilsecurity.demo.server.model.response.CreateUserResponse;
import com.virgilsecurity.demo.server.model.response.NexmoTokenResponse;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.UUID;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * NexmoControllerTest class.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class NexmoControllerTest {

    @LocalServerPort
    int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private String identity;

    @Before
    public void setup() {
        this.identity = UUID.randomUUID().toString();
    }

    @Test
    public void get_nexmo_jwt_no_login() {
        URI uri = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port + "/auth/nexmo-jwt")
                                      .build()
                                      .encode()
                                      .toUri();
        HttpEntity<?> requestEntity = new HttpEntity<>(new HttpHeaders());
        ResponseEntity<NexmoTokenResponse> responseEntity = this.restTemplate.exchange(uri,
                                                                                       HttpMethod.GET,
                                                                                       requestEntity,
                                                                                       NexmoTokenResponse.class);
        assertNotNull(responseEntity);
        assertEquals(401, responseEntity.getStatusCode().value());
    }

    @Test
    public void generateToken() throws URISyntaxException {
        final String baseUrl = "http://localhost:" + port + "/auth/authenticate";
        URI uri = new URI(baseUrl);
        identity = "jamie";
        AuthRequest authRequest = new AuthRequest(identity);

        HttpEntity<AuthRequest> request = new HttpEntity<>(authRequest);

        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(uri, request, AuthResponse.class);

        assertEquals(200, response.getStatusCodeValue());
        String authToken = response.getBody().getAuthToken();

        URI uriNexmoJwt = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port + "/auth/nexmo-jwt")
                                              .build()
                                              .encode().toUri();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + authToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<NexmoTokenResponse> responseEntity = this.restTemplate.exchange(uriNexmoJwt,
                                                                                       HttpMethod.GET,
                                                                                       requestEntity,
                                                                                       NexmoTokenResponse.class);
        assertNotNull(responseEntity);
        assertEquals(200, responseEntity.getStatusCode().value());

        NexmoTokenResponse nexmoTokenResponse = responseEntity.getBody();
        assertNotNull(nexmoTokenResponse);
        assertNotNull(nexmoTokenResponse.getNexmoToken());
    }

    @Test
    public void createUser() throws URISyntaxException {
        final String baseUrl = "http://localhost:" + port + "/auth/authenticate";
        URI uri = new URI(baseUrl);
        AuthRequest authRequest = new AuthRequest(identity);

        HttpEntity<AuthRequest> request = new HttpEntity<>(authRequest);

        ResponseEntity<AuthResponse> response = restTemplate.postForEntity(uri,
                                                                           request,
                                                                           AuthResponse.class);

        assertEquals(200, response.getStatusCodeValue());
        String authToken = response.getBody().getAuthToken();

        URI uriNexmoJwt = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port + "/auth/nexmo-jwt")
                                              .build()
                                              .encode().toUri();
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + authToken);
        HttpEntity<?> requestEntity = new HttpEntity<>(headers);
        ResponseEntity<NexmoTokenResponse> responseEntity = this.restTemplate.exchange(uriNexmoJwt,
                                                                                       HttpMethod.GET,
                                                                                       requestEntity,
                                                                                       NexmoTokenResponse.class);
        assertNotNull(responseEntity);
        assertEquals(200, responseEntity.getStatusCode().value());

        NexmoTokenResponse nexmoTokenResponse = responseEntity.getBody();
        assertNotNull(nexmoTokenResponse);
        assertNotNull(nexmoTokenResponse.getNexmoToken());

        URI uriCreateUser = UriComponentsBuilder.fromHttpUrl("http://localhost:" + port + "/users/create")
                                                .build()
                                                .encode()
                                                .toUri();
        HttpHeaders headersCreateUser = new HttpHeaders();
        headersCreateUser.add("Authorization", "Bearer " + nexmoTokenResponse.getNexmoToken());
        String username = UUID.randomUUID().toString();
        CreateUserRequest createUserRequest = new CreateUserRequest(username, username + "display");
        HttpEntity<CreateUserRequest> requestEntityCreateUser = new HttpEntity<>(createUserRequest,
                                                                                 headersCreateUser);

        ResponseEntity<CreateUserResponse> responseCreateUser = restTemplate.postForEntity(uriCreateUser,
                                                                                           requestEntityCreateUser,
                                                                                           CreateUserResponse.class);

        assertEquals(200, responseCreateUser.getStatusCodeValue());
        CreateUserResponse createUserResult = responseCreateUser.getBody();
        assertNotNull(createUserResult);
    }
}
