/* ========================================================================
 * Copyright (c) 2019 The University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

// package edu.washington.iam.tools;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.Signature;
import java.security.PublicKey;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.Base64;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonElement;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonParseException;


// System.lineSeparator()

public class IamCrypt {

   String encodedMessageFile = "./data/msg.enc";
   String MessageBodyFile = "./data/msg.body";
   private static Base64 b64;

   static {
      Security.addProvider(new BouncyCastleProvider());
   }

   public static void main(String[] args) {
      IamCrypt crypt = new IamCrypt();
      crypt.run();
   }

   public void run() {

      // get the doc ( test file with encoded message )
      String sigdoc = null;
      System.out.println("Processing encoded message from " + encodedMessageFile);
      System.out.println("Original message body text from " + MessageBodyFile);
      try {
         sigdoc = new String(Files.readAllBytes(Paths.get(encodedMessageFile)));
         logit("doc=" + sigdoc);
      } catch (IOException e) {
         logit(e.toString());
      }
     
      // parse
      String certUrl = null;
      JsonObject j_header = null;
      X509Certificate sigcert = null;
      String body64 = null;
      String body = null;
      JsonParser parser = new JsonParser();
      JsonObject obj = parser.parse(sigdoc).getAsJsonObject();
      j_header = obj.getAsJsonObject("header");
      certUrl = getJson(j_header, "signingCertUrl");
      logit(certUrl);
      sigcert = getCertificate(certUrl);
      body64 = getJson(obj, "body");
      logit(body64);

      // verify signature
      try {
         String sigmsg = buildSigMessage(j_header, body64);
         byte[] signature_in = b64.decode(getJson(j_header, "signature"));
         PublicKey sigkey = sigcert.getPublicKey();
      
         Signature signature = Signature.getInstance("SHA256withRSA/PSS");
         signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
         signature.initVerify(sigkey);
         byte[] bsigmsg = sigmsg.getBytes("UTF-8");
         signature.update(bsigmsg);
         boolean isCorrect = signature.verify(signature_in);
         if (isCorrect) System.out.println("Signature good.");
         else logit ("no");
      } catch (NoSuchAlgorithmException e) {
         logit(e.toString());
      } catch (InvalidAlgorithmParameterException e) {
         logit(e.toString());
      } catch (InvalidKeyException e) {
         logit(e.toString());
      } catch (UnsupportedEncodingException e) {
         logit(e.toString());
      } catch (SignatureException e) {
         logit(e.toString());
      }

      // decrypt
      if (getJson(j_header, "iv") != null) {
         try {
            byte[] iv64 = getJson(j_header, "iv").getBytes("UTF-8");
            byte[] ivb = b64.decode(iv64);
            IvParameterSpec iv = new IvParameterSpec(ivb);
            byte[] key = b64.decode("OWJlZmZkOTQ5YTVkNDBmNWEyNzQwZWRiNzY4MmFkNzc=");
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] dec64 = cipher.doFinal(b64.decode(body64));
            logit(new String(dec64));
            body = new String(dec64);
            System.out.println("Document decrypts ok.");
         } catch (UnsupportedEncodingException e) {
            logit(e.toString());
         } catch (NoSuchAlgorithmException e) {
            logit(e.toString());
         } catch (InvalidKeyException e) {
            logit(e.toString());
         } catch (IllegalBlockSizeException e) {
            logit(e.toString());
         } catch (NoSuchPaddingException e) {
            logit(e.toString());
         } catch (InvalidAlgorithmParameterException e) {
            logit(e.toString());
         } catch (BadPaddingException e) {
            logit(e.toString());
         }
      } else {
         body = new String(body64);
      }
      logit(body);

      /* Verify the message data */
      try {
         String orig = new String(Files.readAllBytes(Paths.get(MessageBodyFile)));
         logit("doc=" + orig);
         if (orig.equals(body)) System.out.println("Message body matches.");
      } catch (IOException e) {
         logit(e.toString());
      }
   }

   private String getJson(JsonObject obj, String key) {
      JsonPrimitive p = obj.getAsJsonPrimitive(key);
      if (p==null) return null;
      return p.getAsString();
   }
   private void logit(String msg) {
      // System.out.println(msg);
   }

   private String buildSigMessage(JsonObject header, String msg) {
      String sigmsg = getJson(header, "contentType") + "\n";
      if (header.get("keyId") != null) {
         logit("adding header");
         sigmsg = sigmsg + getJson(header, "iv") + "\n" + getJson(header, "keyId") + "\n";
      }
      sigmsg = sigmsg + getJson(header, "messageContext") + "\n" +
                        getJson(header, "messageId") + "\n" +
                        getJson(header, "messageType") + "\n" +
                        getJson(header, "sender") + "\n" +
                        getJson(header, "signingCertUrl") + "\n" +
                        getJson(header, "timestamp") + "\n" +
                        getJson(header, "version") + "\n" +
                        msg + "\n";
      logit("sigmsg=" + sigmsg);
      return sigmsg;
   }
   private X509Certificate getCertificate(String certUrl) {
      
      FileInputStream file;
      X509Certificate cert = null;

      if (certUrl.startsWith("file:")) {
         String certFile = certUrl.substring(5);
         logit("certfile: " + certFile);
         try {
            file = new FileInputStream(certFile);
         } catch (IOException e) {
            logit("bad cert file: " + e);
            return null;
         }
         try {
             CertificateFactory cf = CertificateFactory.getInstance("X.509");
             cert = (X509Certificate) cf.generateCertificate(file);
         } catch (CertificateException e) {
             logit("bad cert: " + e);
             return null;
         }
      }
      return cert;
   }
}

