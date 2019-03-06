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

package com.virgilsecurity.demo.server.model.jwt;

/**
 * NexmoAcl class.
 */
public enum NexmoAcl {

    USERS("\"/v1/users/**\":{}"),
    CONVERSATIONS("\"/v1/conversations/**\":{}"),
    SESSIONS("\"/v1/sessions/**\":{}"),
    DEVICES("\"/v1/devices/**\":{}"),
    IMAGE("\"/v1/image/**\":{}"),
    MEDIA("\"/v1/media/**\":{}"),
    APPLIACTIONS("\"/v1/applications/**\":{}"),
    PUSH("\"/v1/push/**\":{}"),
    KNOCKING("\"/v1/knocking/**\":{}"),
    ADMIN("\"/**\":{}");

    private final String acl;

    private NexmoAcl(String acl) {
        this.acl = acl;
    }

    public boolean equalsName(String otherAcl) {
        // (otherName == null) check is not needed because name.equals(null) returns false
        return acl.equals(otherAcl);
    }

    public String toString() {
        return this.acl;
    }
}
