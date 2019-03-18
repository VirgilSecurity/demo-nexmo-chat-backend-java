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

import com.virgilsecurity.demo.server.model.request.CreateUserRequest;
import com.virgilsecurity.demo.server.model.response.CreateUserResponse;
import com.virgilsecurity.demo.server.model.response.NexmoTokenResponse;
import com.virgilsecurity.demo.server.service.AuthenticationService;
import com.virgilsecurity.demo.server.service.NexmoService;
import com.virgilsecurity.demo.server.util.JwtVerifierNexmo;
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

/**
 * NexmoController class.
 */
@RestController
public class NexmoController {

    @Autowired
    NexmoService nexmoService;
    @Autowired
    AuthenticationService authService;
    @Autowired
    JwtVerifierNexmo jwtVerifierNexmo;

    @RequestMapping("/auth/nexmo-jwt")
    public ResponseEntity<NexmoTokenResponse> getNexmoToken(
            @RequestHeader(name = "Authorization", required = false)
                String authToken) throws GeneralSecurityException, IOException {
        String identity = authService.getIdentity(authToken);
        if (identity == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        String token = nexmoService.generateNexmoToken(identity);

        if (!jwtVerifierNexmo.verify(token))
            throw new IllegalStateException("Sorry, I've generated bad token.");

        return new ResponseEntity<>(new NexmoTokenResponse(token), HttpStatus.OK);
    }

    @PostMapping
    @RequestMapping("/users/create")
    public ResponseEntity<CreateUserResponse> createUser(
        @RequestBody CreateUserRequest authRequest) throws GeneralSecurityException, IOException {
        CreateUserResponse response;
        try {
            response = nexmoService.createUser(authRequest.getName(),
                                               authRequest.getDisplayName());
        } catch (HttpClientErrorException exception) {
            if (exception.getStatusCode().value() == HttpStatus.BAD_REQUEST.value())
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            else
                return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
