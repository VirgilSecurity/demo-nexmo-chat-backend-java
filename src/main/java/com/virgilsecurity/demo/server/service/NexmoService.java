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

package com.virgilsecurity.demo.server.service;

import com.virgilsecurity.demo.server.model.request.CreateUserRequest;
import com.virgilsecurity.demo.server.model.response.CreateUserResponse;
import com.virgilsecurity.demo.server.util.JwtGeneratorNexmo;
import com.virgilsecurity.demo.server.util.NexmoAcl;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

/**
 * NexmoService class.
 */
@Service
public class NexmoService {

  private static final String BASE_URL = "https://api.nexmo.com/beta";
  private static final String USERS = "/users";

  @Autowired
  JwtGeneratorNexmo jwtGeneratorNexmo;

  public String generateNexmoToken(String identity) throws GeneralSecurityException, IOException {
    List<NexmoAcl> aclList = new ArrayList<>(2);
    aclList.add(NexmoAcl.SESSIONS);
    aclList.add(NexmoAcl.CONVERSATIONS);
    aclList.add(NexmoAcl.USERS);

    return jwtGeneratorNexmo.generate(identity, aclList);
  }

  public CreateUserResponse createUser(String name, String displayName) {
    CreateUserRequest newEmployee = new CreateUserRequest(name, displayName);
    RestTemplate restTemplate = new RestTemplate();

    return restTemplate.postForObject(BASE_URL + USERS, newEmployee, CreateUserResponse.class);
  }
}
