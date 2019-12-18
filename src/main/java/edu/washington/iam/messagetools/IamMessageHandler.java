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

package edu.washington.iam.messaging;

import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.spec.PSSParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import java.util.Hashtable;
import java.util.Iterator;
import java.util.Map;

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


public class IamMessageHandler {

   private static Base64 b64;

   static {
      Security.addProvider(new BouncyCastleProvider());
   }

   /* List of signing certs by url (for verify) */
   Map signingCerts = new Hashtable<String, X509Certificate>();
   
   /* List of signing keys (for sign) */
   private class SigningKey {
      public String url;  // public key url
      public PrivateKey key;
   }
   Map signingKeys = new Hashtable<String, PrivateKey>();

   /* Add a private key for signing operation */
   public void addSigningKey(String id, String url, String keyfile) {
      SigningKey key = new SigningKey();
      key.url = url;
      key.key = getPrivateKey(keyfile);
      signingKeys.put(id, key);
   }
   
   /* List of cryption keys */
   Map cryptKeys = new Hashtable<String, byte[]>();
   
   /* Add a crypt key */
   public void addCryptKey(String id, String key64) {
      cryptKeys.put(id, b64.decode(key64));
   }

   /* CA filename */
   private String ca_file = null;

   /* parse an encoded message ( with signature verify and possible decryption ) */

   public IamMessage parse(String encodedMessage) throws IamMessageException {

      IamMessage message = new IamMessage();
      String certUrl = null;
      JsonObject j_header = null;
      String body64 = null;
      String body = null;
      JsonParser parser = new JsonParser();
      JsonObject obj = parser.parse(encodedMessage).getAsJsonObject();
      j_header = obj.getAsJsonObject("header");
      certUrl = getJson(j_header, "signingCertUrl");
      logit(certUrl);

      // verify this is message we can handle
      String vers = getJson(j_header, "version");
      if (!vers.equals("UWIT-2")) throw new IamMessageException("unknown version: " + vers);
      message.setVersion(vers);
      message.setContentType(getJson(j_header, "contentType"));
      message.setMessageContext(getJson(j_header, "messageContext"));
      message.setMessageId(getJson(j_header, "messageId"));
      message.setMessageType(getJson(j_header, "messageType"));
      message.setSender(getJson(j_header, "sender"));
      message.setTimestamp(getJson(j_header, "timestamp"));
      message.setSigningCertUrl(certUrl);
      message.setIv(getJson(j_header, "iv"));
      message.setKeyId(getJson(j_header, "keyId"));

      body64 = getJson(obj, "body");
      logit(body64);

      // verify signature
      try {
         X509Certificate sigcert = getCertificate(certUrl);
         String sigmsg = buildSigMessage(message, body64);
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

      // decrypt as needed
      if (message.getKeyId()!=null) {
         try {
            byte[] iv64 = message.getIv().getBytes("UTF-8");
            byte[] ivb = b64.decode(iv64);
            IvParameterSpec iv = new IvParameterSpec(ivb);
            byte[] key = (byte[]) cryptKeys.get(message.getKeyId());
            SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] dec64 = cipher.doFinal(b64.decode(body64));
            logit(new String(dec64));
            message.setBody(new String(dec64));
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
         message.setBody(new String(body64));
      }
      return message;
   }

   private String getJson(JsonObject obj, String key) {
      JsonPrimitive p = obj.getAsJsonPrimitive(key);
      if (p==null) return null;
      return p.getAsString();
   }
   private void logit(String msg) {
      System.out.println(msg);
   }

   /* USE the IamMessage object */
   private String buildSigMessage(IamMessage msg, String body64) {
      String sigmsg = msg.getContentType() + "\n";
      if (msg.getKeyId() != null) {
         logit("adding header");
         sigmsg = sigmsg + msg.getIv() + "\n" + msg.getKeyId() + "\n";
      }
      sigmsg = sigmsg + msg.getMessageContext() + "\n" +
                        msg.getMessageId() + "\n" +
                        msg.getMessageType() + "\n" +
                        msg.getSender() + "\n" +
                        msg.getSigningCertUrl() + "\n" +
                        msg.getTimestamp() + "\n" +
                        msg.getVersion() + "\n" +
                        body64 + "\n";
      logit("sigmsg=[" + sigmsg + "]");
      return sigmsg;
   }
   /* USE the IamMessage object */
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

   /* Read a certificate from a PEM file */
   private X509Certificate getCertificate(String certUrl) {
      
      FileInputStream file;
      X509Certificate cert = null;

      if (signingCerts.containsKey(certUrl)) return (X509Certificate) signingCerts.get(certUrl);

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
      signingCerts.put(certUrl, cert);
      return cert;
   }

   /* Read a private key from a PEM file */
   private PrivateKey getPrivateKey(String keyUrl) {
      
      PrivateKey key = null;

      if (signingKeys.containsKey(keyUrl)) return (PrivateKey) signingKeys.get(keyUrl);

      if (keyUrl.startsWith("file:")) {
         String keyFile = keyUrl.substring(5);
         logit("keyfile: " + keyFile);
         try {
            FileInputStream file = new FileInputStream(keyFile);
            byte[] keyBytes = new byte[file.available()];
            file.read(keyBytes);
            file.close();
            String keyString = new String(keyBytes, "UTF-8");
            // remove any leading, trailing test
            keyString = keyString.replaceAll("(-+BEGIN RSA PRIVATE KEY-+\\r?\\n|-+END RSA PRIVATE KEY-+\\r?\\n?)", "");
            keyBytes = b64.decode(keyString);
 
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            key = keyFactory.generatePrivate(spec);
            cryptKeys.put(keyUrl, key);
            return key;
         } catch (IOException e) {
            logit("bad key file: " + e);
         } catch (InvalidKeySpecException e) {
            logit(e.toString());
         } catch (NoSuchAlgorithmException e) {
            logit(e.toString());
         }
      }
      if (key!=null) signingKeys.put(keyUrl, key);
      return key;
   }

   public void init(String configFile) {
      try {
         FileInputStream file = new FileInputStream(configFile);
         byte[] keyBytes = new byte[file.available()];
         file.read(keyBytes);
         file.close();
         String configString = new String(keyBytes, "UTF-8");
         logit(configString);

         JsonParser parser = new JsonParser();
         JsonObject obj = parser.parse(configString).getAsJsonObject();

         JsonArray certs = obj.getAsJsonArray("certs");
         Iterator it = certs.iterator();
         while (it.hasNext()) {
            JsonObject certobj = ((JsonObject)it.next()).getAsJsonObject();
            String id = getJson(certobj,"id");
            String url = getJson(certobj,"url");
            String keyfile = getJson(certobj,"keyfile");
            logit("cert id = " + id);
            addSigningKey(id, url, keyfile);
         }

         JsonArray crypts = obj.getAsJsonArray("crypts");
         it = crypts.iterator();
         while (it.hasNext()) {
            JsonObject cryptobj = ((JsonObject)it.next()).getAsJsonObject();
            String id = getJson(cryptobj,"id");
            String key = getJson(cryptobj,"key");
            logit("crypt id = " + id);
            addCryptKey(id, key);
         }
         ca_file = getJson(obj, "ca_file");
      } catch (IOException e) {
         logit("bad key file: " + e);
      }
      
   }


}


