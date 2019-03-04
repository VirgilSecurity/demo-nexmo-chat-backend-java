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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import org.apache.tomcat.util.codec.binary.Base64;

/**
 * KeyUtils class.
 */
class KeyUtils {

  static PublicKey extractPublicKey(PrivateKey privateKey) throws
      NoSuchAlgorithmException, InvalidKeySpecException {

    RSAPrivateCrtKey privateKeyRsaCert = (RSAPrivateCrtKey) privateKey;
    RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privateKeyRsaCert.getModulus(),
                                                          privateKeyRsaCert.getPublicExponent());
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");

    return keyFactory.generatePublic(publicKeySpec);
  }

  private static String getKey(String filename) throws IOException {
    StringBuilder strKeyPEM = new StringBuilder();
    BufferedReader br = new BufferedReader(new FileReader(filename));
    String line;
    while ((line = br.readLine()) != null) {
      strKeyPEM.append(line).append("\n");
    }
    br.close();
    return strKeyPEM.toString();
  }

  /**
   * Constructs a private key (RSA) from the given file
   *
   * @param filename PEM Private Key
   *
   * @return RSA Private Key
   */
  static RSAPrivateKey getPrivateKey(String filename) throws IOException, GeneralSecurityException {
    String privateKeyPEM = getKey(filename);
    return getPrivateKeyFromString(privateKeyPEM);
  }

  /**
   * Constructs a private key (RSA) from the given string
   *
   * @param key PEM Private Key
   *
   * @return RSA Private Key
   */
  private static RSAPrivateKey getPrivateKeyFromString(String key) throws GeneralSecurityException {
    String privateKeyPEM = key;

    // Remove the first and last lines
    privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----\n", "");
    privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----\n", "");

    // Base64 decode data
    byte[] encoded = Base64.decodeBase64(privateKeyPEM);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(encoded));
  }

  /**
   * Constructs a public key (RSA) from the given file
   *
   * @param filename PEM Public Key
   *
   * @return RSA Public Key
   */
  public static RSAPublicKey getPublicKey(String filename) throws IOException, GeneralSecurityException {
    String publicKeyPEM = getKey(filename);
    return getPublicKeyFromString(publicKeyPEM);
  }

  /**
   * Constructs a public key (RSA) from the given string
   *
   * @param key PEM Public Key
   *
   * @return RSA Public Key
   */
  private static RSAPublicKey getPublicKeyFromString(String key) throws GeneralSecurityException {
    String publicKeyPEM = key;

    // Remove the first and last lines
    publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----n", "");
    publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");

    // Base64 decode data
    byte[] encoded = Base64.decodeBase64(publicKeyPEM);

    KeyFactory kf = KeyFactory.getInstance("RSA");
    return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
  }

  static String sign(PrivateKey privateKey,
                     String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature sign = Signature.getInstance("SHA1withRSA");
    sign.initSign(privateKey);
    sign.update(message.getBytes(StandardCharsets.UTF_8));
    return new String(Base64.encodeBase64(sign.sign()), StandardCharsets.UTF_8);
  }

  static boolean verify(PublicKey publicKey,
                        String message,
                        String signature) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    Signature sign = Signature.getInstance("SHA1withRSA");
    sign.initVerify(publicKey);
    sign.update(message.getBytes(StandardCharsets.UTF_8));
    return sign.verify(Base64.decodeBase64(signature.getBytes(StandardCharsets.UTF_8)));
  }

  public static String encrypt(String rawText,
                               PublicKey publicKey) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Decrypts the text with the private key (RSA)
   *
   * @param cipherText Text to be decrypted
   *
   * @return Decrypted text (Base64 encoded)
   */
  public static String decrypt(String cipherText,
                               PrivateKey privateKey) throws GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, privateKey);
    return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), StandardCharsets.UTF_8);
  }
}
