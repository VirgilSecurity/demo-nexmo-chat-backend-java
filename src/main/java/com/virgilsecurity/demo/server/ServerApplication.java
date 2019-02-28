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

package com.virgilsecurity.demo.server;

import com.virgilsecurity.demo.server.util.JwtGeneratorNexmo;
import com.virgilsecurity.demo.server.util.JwtVerifierNexmo;
import com.virgilsecurity.sdk.common.TimeSpan;
import com.virgilsecurity.sdk.crypto.AccessTokenSigner;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.VirgilAccessTokenSigner;
import com.virgilsecurity.sdk.crypto.VirgilCrypto;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.jwt.JwtGenerator;
import com.virgilsecurity.sdk.utils.ConvertionUtils;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class ServerApplication {

    @Value("${virgil.app.id}")
    String appId;

    @Value("${virgil.api.private_key}")
    String apiKey;

    @Value("${virgil.api.public_key_id}")
    String apiKeyIdentifier;

    @Value("${nexmo.api.secret_key}")
    String nexmoSecretKey;

    @Value("${nexmo.api.app_id}")
    String nexmoAppId;

    public static void main(String[] args) {
        SpringApplication.run(ServerApplication.class, args);
    }

    @Bean
    public JwtGenerator jwtGenerator() throws CryptoException {
        VirgilCrypto crypto = new VirgilCrypto();
        PrivateKey privateKey = crypto.importPrivateKey(ConvertionUtils.base64ToBytes(this.apiKey));
        AccessTokenSigner accessTokenSigner = new VirgilAccessTokenSigner();

        return new JwtGenerator(appId, privateKey, apiKeyIdentifier,
                                TimeSpan.fromTime(1, TimeUnit.HOURS), accessTokenSigner);
    }

    @Bean
    public JwtGeneratorNexmo jwtGeneratorNexmo() {

        return new JwtGeneratorNexmo(nexmoSecretKey,
                                     nexmoAppId,
                                     TimeSpan.fromTime(2, TimeUnit.HOURS));
    }

    @Bean
    public JwtVerifierNexmo jwtVerifierNexmo() {
        return new JwtVerifierNexmo(nexmoSecretKey);
    }
}
