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

package com.virgilsecurity.demo.server.util;

import com.auth0.jwt.algorithms.Algorithm;
import com.virgilsecurity.sdk.common.TimeSpan;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * JwtGeneratorNexmo class.
 */
public class JwtGeneratorNexmo {

    private static final String TYPE = "typ";
    private static final String ALGORITHM = "alg";
    private static final String ISSUED_AT = "iat";
    private static final String JWT_ID = "jti";
    private static final String SUBJECT = "sub";
    private static final String EXPITAION = "exp";
    private static final String ACL = "acl";
    private static final String PATHS = "paths";
    private static final String APP_ID = "application_id";

    private static final String TYPE_JWT = "JWT";
    private static final String ALGORITHM_RS256 = "RS256";

    private final String secretKey;
    private final String appId;
    private final TimeSpan ttl;

    public JwtGeneratorNexmo(String secretKey, String appId, TimeSpan ttl) {
        this.secretKey = secretKey;
        this.appId = appId;
        this.ttl = ttl;
    }

    public String generate(String identity,
                           List<NexmoAcl> acls) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey privateKey = kf.generatePrivate(keySpec);

        Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) privateKey);

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        String issuedAt = String.valueOf(now.getTime() / 1000);
        String expiresAt = String.valueOf((now.getTime() / 1000) + ttl.getSpanSeconds());

        StringBuilder aclBuilder = new StringBuilder();
        aclBuilder.append("  \"" + ACL+ "\": {\n");
        aclBuilder.append("    \"" + PATHS + "\": {\n");
        for (int i = 0; i < acls.size(); i++) {
            aclBuilder.append(acls.get(i).toString());

            if (i < acls.size() - 1)
                aclBuilder.append(','); // Do not add comma on the last line

            aclBuilder.append('\n');
        }
        aclBuilder.append("    }\n");
        aclBuilder.append("  },\n");

        String headerJson = "{\n" +
                "  \"" + TYPE + "\": \"" + TYPE_JWT + "\",\n" +
                "  \"" + ALGORITHM + "\": \"" + ALGORITHM_RS256 + "\"\n" +
                "}";

        String payloadJson = "{\n" +
                "  \"" + ISSUED_AT + "\": " + issuedAt + ",\n" +
                "  \"" + JWT_ID + "\": \"" + UUID.randomUUID().toString() + "\",\n" +
                "  \"" + SUBJECT + "\": \"" + identity + "\",\n" +
                "  \"" + EXPITAION + "\": \"" + expiresAt + "\",\n" +
                aclBuilder.toString() +
                "  \"" + APP_ID + "\": \"" + appId + "\"\n" +
                "}";


        String headerEncoded = org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(headerJson.getBytes());
        String payloadEncoded = org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(payloadJson.getBytes());

        byte[] signatureBytes = algorithm.sign(headerEncoded.getBytes(), payloadEncoded.getBytes());
        String signature = org.apache.tomcat.util.codec.binary.Base64.encodeBase64String(signatureBytes);

        return String.format("%s.%s.%s", headerEncoded, payloadEncoded, signature);
    }
}
