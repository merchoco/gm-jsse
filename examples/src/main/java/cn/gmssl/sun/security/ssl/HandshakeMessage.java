package cn.gmssl.sun.security.ssl;

import cn.gmssl.crypto.impl.sm2.SM2Util;
import cn.gmssl.sun.security.internal.spec.TlsPrfParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.DigestException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLKeyException;
import javax.net.ssl.SSLProtocolException;
import javax.security.auth.x500.X500Principal;
import org.bc.math.ec.ECCurve;

public abstract class HandshakeMessage {
   static final byte ht_hello_request = 0;
   static final byte ht_client_hello = 1;
   static final byte ht_server_hello = 2;
   static final byte ht_certificate = 11;
   static final byte ht_server_key_exchange = 12;
   static final byte ht_certificate_request = 13;
   static final byte ht_server_hello_done = 14;
   static final byte ht_certificate_verify = 15;
   static final byte ht_client_key_exchange = 16;
   static final byte ht_finished = 20;
   public static final Debug debug = Debug.getInstance("ssl");
   static final byte[] MD5_pad1 = genPad(54, 48);
   static final byte[] MD5_pad2 = genPad(92, 48);
   static final byte[] SHA_pad1 = genPad(54, 40);
   static final byte[] SHA_pad2 = genPad(92, 40);

   static byte[] toByteArray(BigInteger var0) {
      byte[] var1 = var0.toByteArray();
      if (var1.length > 1 && var1[0] == 0) {
         int var2 = var1.length - 1;
         byte[] var3 = new byte[var2];
         System.arraycopy(var1, 1, var3, 0, var2);
         var1 = var3;
      }

      return var1;
   }

   private static byte[] genPad(int var0, int var1) {
      byte[] var2 = new byte[var1];
      Arrays.fill(var2, (byte)var0);
      return var2;
   }

   final void write(HandshakeOutStream var1) throws IOException {
      int var2 = this.messageLength();
      if (var2 > 16777216) {
         throw new SSLException("Handshake message too big, type = " + this.messageType() + ", len = " + var2);
      } else {
         var1.write(this.messageType());
         var1.putInt24(var2);
         this.send(var1);
      }
   }

   abstract int messageType();

   abstract int messageLength();

   abstract void send(HandshakeOutStream var1) throws IOException;

   abstract void print(PrintStream var1) throws IOException;

   static final class CertificateMsg extends HandshakeMessage {
      private X509Certificate[] chain;
      private List<byte[]> encodedChain;
      private int messageLength;

      int messageType() {
         return 11;
      }

      CertificateMsg(X509Certificate[] var1) {
         this.chain = var1;
      }

      CertificateMsg(HandshakeInStream var1) throws IOException {
         int var2 = var1.getInt24();
         ArrayList var3 = new ArrayList(4);
         CertificateFactory var4 = null;

         while(var2 > 0) {
            byte[] var5 = var1.getBytes24();
            var2 -= 3 + var5.length;

            try {
               if (var4 == null) {
                  var4 = CertificateFactory.getInstance("X.509", "GMJCE");
               }

               var3.add(var4.generateCertificate(new ByteArrayInputStream(var5)));
            } catch (CertificateException var7) {
               throw (SSLProtocolException)(new SSLProtocolException(var7.getMessage())).initCause(var7);
            } catch (NoSuchProviderException var8) {
               throw (SSLProtocolException)(new SSLProtocolException(var8.getMessage())).initCause(var8);
            }
         }

         this.chain = (X509Certificate[])var3.toArray(new X509Certificate[var3.size()]);
      }

      int messageLength() {
         if (this.encodedChain == null) {
            this.messageLength = 3;
            this.encodedChain = new ArrayList(this.chain.length);

            try {
               X509Certificate[] var4 = this.chain;
               int var3 = this.chain.length;

               for(int var2 = 0; var2 < var3; ++var2) {
                  X509Certificate var1 = var4[var2];
                  byte[] var5 = var1.getEncoded();
                  this.encodedChain.add(var5);
                  this.messageLength += var5.length + 3;
               }
            } catch (CertificateEncodingException var6) {
               this.encodedChain = null;
               throw new RuntimeException("Could not encode certificates", var6);
            }
         }

         return this.messageLength;
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putInt24(this.messageLength() - 3);
         Iterator var3 = this.encodedChain.iterator();

         while(var3.hasNext()) {
            byte[] var2 = (byte[])var3.next();
            var1.putBytes24(var2);
         }

      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** Certificate chain");
         if (debug != null && Debug.isOn("verbose")) {
            for(int var2 = 0; var2 < this.chain.length; ++var2) {
               var1.println("chain [" + var2 + "] = " + this.chain[var2]);
            }

            var1.println("***");
         }

      }

      X509Certificate[] getCertificateChain() {
         return (X509Certificate[])this.chain.clone();
      }
   }

   static final class CertificateRequest extends HandshakeMessage {
      static final int cct_rsa_sign = 1;
      static final int cct_dss_sign = 2;
      static final int cct_rsa_fixed_dh = 3;
      static final int cct_dss_fixed_dh = 4;
      static final int cct_rsa_ephemeral_dh = 5;
      static final int cct_dss_ephemeral_dh = 6;
      static final int cct_ecdsa_sign = 64;
      static final int cct_rsa_fixed_ecdh = 65;
      static final int cct_ecdsa_fixed_ecdh = 66;
      private static final byte[] TYPES_NO_ECC = new byte[]{1, 2};
      private static final byte[] TYPES_ECC = new byte[]{1, 2, 64};
      byte[] types;
      HandshakeMessage.DistinguishedName[] authorities;
      ProtocolVersion protocolVersion;
      private Collection<SignatureAndHashAlgorithm> algorithms;
      private int algorithmsLen;

      CertificateRequest(X509Certificate[] var1, CipherSuite.KeyExchange var2, Collection<SignatureAndHashAlgorithm> var3, ProtocolVersion var4) throws IOException {
         this.protocolVersion = var4;
         this.authorities = new HandshakeMessage.DistinguishedName[var1.length];

         for(int var5 = 0; var5 < var1.length; ++var5) {
            X500Principal var6 = var1[var5].getSubjectX500Principal();
            this.authorities[var5] = new HandshakeMessage.DistinguishedName(var6);
         }

         this.types = JsseJce.isEcAvailable() ? TYPES_ECC : TYPES_NO_ECC;
         if (var4.v >= ProtocolVersion.TLS12.v) {
            if (var3 == null || var3.isEmpty()) {
               throw new SSLProtocolException("No supported signature algorithms");
            }

            this.algorithms = new ArrayList(var3);
            this.algorithmsLen = SignatureAndHashAlgorithm.sizeInRecord() * this.algorithms.size();
         } else {
            this.algorithms = new ArrayList();
            this.algorithmsLen = 0;
         }

      }

      CertificateRequest(HandshakeInStream var1, ProtocolVersion var2) throws IOException {
         this.protocolVersion = var2;
         this.types = var1.getBytes8();
         int var3;
         if (var2.v >= ProtocolVersion.TLS12.v) {
            this.algorithmsLen = var1.getInt16();
            if (this.algorithmsLen < 2) {
               throw new SSLProtocolException("Invalid supported_signature_algorithms field");
            }

            this.algorithms = new ArrayList();
            var3 = this.algorithmsLen;

            for(int var4 = 0; var3 > 1; var3 -= 2) {
               int var5 = var1.getInt8();
               int var6 = var1.getInt8();
               ++var4;
               SignatureAndHashAlgorithm var7 = SignatureAndHashAlgorithm.valueOf(var5, var6, var4);
               this.algorithms.add(var7);
            }

            if (var3 != 0) {
               throw new SSLProtocolException("Invalid supported_signature_algorithms field");
            }
         } else {
            this.algorithms = new ArrayList();
            this.algorithmsLen = 0;
         }

         var3 = var1.getInt16();

         ArrayList var8;
         HandshakeMessage.DistinguishedName var9;
         for(var8 = new ArrayList(); var3 >= 3; var3 -= var9.length()) {
            var9 = new HandshakeMessage.DistinguishedName(var1);
            var8.add(var9);
         }

         if (var3 != 0) {
            throw new SSLProtocolException("Bad CertificateRequest DN length");
         } else {
            this.authorities = (HandshakeMessage.DistinguishedName[])var8.toArray(new HandshakeMessage.DistinguishedName[var8.size()]);
         }
      }

      X500Principal[] getAuthorities() throws IOException {
         X500Principal[] var1 = new X500Principal[this.authorities.length];

         for(int var2 = 0; var2 < this.authorities.length; ++var2) {
            var1[var2] = this.authorities[var2].getX500Principal();
         }

         return var1;
      }

      Collection<SignatureAndHashAlgorithm> getSignAlgorithms() {
         return this.algorithms;
      }

      int messageType() {
         return 13;
      }

      int messageLength() {
         int var1 = 1 + this.types.length + 2;
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            var1 += this.algorithmsLen + 2;
         }

         for(int var2 = 0; var2 < this.authorities.length; ++var2) {
            var1 += this.authorities[var2].length();
         }

         return var1;
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putBytes8(this.types);
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            var1.putInt16(this.algorithmsLen);
            Iterator var3 = this.algorithms.iterator();

            while(var3.hasNext()) {
               SignatureAndHashAlgorithm var2 = (SignatureAndHashAlgorithm)var3.next();
               var1.putInt8(var2.getHashValue());
               var1.putInt8(var2.getSignatureValue());
            }
         }

         int var4 = 0;

         int var5;
         for(var5 = 0; var5 < this.authorities.length; ++var5) {
            var4 += this.authorities[var5].length();
         }

         var1.putInt16(var4);

         for(var5 = 0; var5 < this.authorities.length; ++var5) {
            this.authorities[var5].send(var1);
         }

      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** CertificateRequest");
         if (debug != null && Debug.isOn("verbose")) {
            var1.print("Cert Types: ");

            int var2;
            for(var2 = 0; var2 < this.types.length; ++var2) {
               switch(this.types[var2]) {
               case 1:
                  var1.print("RSA");
                  break;
               case 2:
                  var1.print("DSS");
                  break;
               case 3:
                  var1.print("Fixed DH (RSA sig)");
                  break;
               case 4:
                  var1.print("Fixed DH (DSS sig)");
                  break;
               case 5:
                  var1.print("Ephemeral DH (RSA sig)");
                  break;
               case 6:
                  var1.print("Ephemeral DH (DSS sig)");
                  break;
               case 64:
                  var1.print("ECDSA");
                  break;
               case 65:
                  var1.print("Fixed ECDH (RSA sig)");
                  break;
               case 66:
                  var1.print("Fixed ECDH (ECDSA sig)");
                  break;
               default:
                  var1.print("Type-" + (this.types[var2] & 255));
               }

               if (var2 != this.types.length - 1) {
                  var1.print(", ");
               }
            }

            var1.println();
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               StringBuffer var6 = new StringBuffer();
               boolean var3 = false;
               Iterator var5 = this.algorithms.iterator();

               while(var5.hasNext()) {
                  SignatureAndHashAlgorithm var4 = (SignatureAndHashAlgorithm)var5.next();
                  if (var3) {
                     var6.append(", " + var4.getAlgorithmName());
                  } else {
                     var6.append(var4.getAlgorithmName());
                     var3 = true;
                  }
               }

               var1.println("Supported Signature Algorithms: " + var6);
            }

            var1.println("Cert Authorities:");
            if (this.authorities.length == 0) {
               var1.println("<Empty>");
            } else {
               for(var2 = 0; var2 < this.authorities.length; ++var2) {
                  this.authorities[var2].print(var1);
               }
            }
         }

      }
   }

   static final class CertificateVerify extends HandshakeMessage {
      private byte[] signature;
      ProtocolVersion protocolVersion;
      private SignatureAndHashAlgorithm preferableSignatureAlgorithm = null;
      private static final Class delegate;
      private static final Field spiField;
      private static final Object NULL_OBJECT;
      private static final Map<Class, Object> methodCache;

      static {
         try {
            delegate = Class.forName("java.security.MessageDigest$Delegate");
            spiField = delegate.getDeclaredField("digestSpi");
         } catch (Exception var1) {
            throw new RuntimeException("Reflection failed", var1);
         }

         makeAccessible(spiField);
         NULL_OBJECT = new Object();
         methodCache = new ConcurrentHashMap();
      }

      CertificateVerify(ProtocolVersion var1, HandshakeHash var2, PrivateKey var3, SecretKey var4, SecureRandom var5, SignatureAndHashAlgorithm var6, PublicKey var7, byte[] var8) throws GeneralSecurityException {
         this.protocolVersion = var1;
         String var9 = var3.getAlgorithm();
         Signature var10 = null;
         if (var1.major == 1) {
            var10 = SM2Util.sm2Sign(var3, var7);
         } else if (var1.v >= ProtocolVersion.TLS12.v) {
            this.preferableSignatureAlgorithm = var6;
            var10 = JsseJce.getSignature(var6.getAlgorithmName());
            var10.initSign(var3, var5);
         } else {
            var10 = getSignature(var1, var9);
            var10.initSign(var3, var5);
         }

         updateSignature(var10, var1, var2, var9, var4);
         this.signature = var10.sign();
      }

      CertificateVerify(HandshakeInStream var1, Collection<SignatureAndHashAlgorithm> var2, ProtocolVersion var3) throws IOException {
         this.protocolVersion = var3;
         if (var3.v >= ProtocolVersion.TLS12.v) {
            int var4 = var1.getInt8();
            int var5 = var1.getInt8();
            this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.valueOf(var4, var5, 0);
            if (!var2.contains(this.preferableSignatureAlgorithm)) {
               throw new SSLHandshakeException("Unsupported SignatureAndHashAlgorithm in ServerKeyExchange message");
            }
         }

         this.signature = var1.getBytes16();
      }

      SignatureAndHashAlgorithm getPreferableSignatureAlgorithm() {
         return this.preferableSignatureAlgorithm;
      }

      boolean verify(ProtocolVersion var1, HandshakeHash var2, PublicKey var3, SecretKey var4, String var5, byte[] var6) throws GeneralSecurityException {
         String var7 = var3.getAlgorithm();
         Signature var8 = null;
         if (var1.major == 1) {
            var8 = JsseJce.getSignature("SM3withSM2");
         } else if (var1.v >= ProtocolVersion.TLS12.v) {
            var8 = JsseJce.getSignature(this.preferableSignatureAlgorithm.getAlgorithmName());
         } else {
            var8 = getSignature(var1, var7);
         }

         var8.initVerify(var3);
         updateSignature(var8, var1, var2, var7, var4);
         return var8.verify(this.signature);
      }

      private static Signature getSignature(ProtocolVersion var0, String var1) throws GeneralSecurityException {
         if (var1.equals("RSA")) {
            return RSASignature.getInternalInstance();
         } else if (var1.equals("DSA")) {
            return JsseJce.getSignature("RawDSA");
         } else if (var1.equals("EC")) {
            return JsseJce.getSignature("NONEwithECDSA");
         } else {
            throw new SignatureException("Unrecognized algorithm: " + var1);
         }
      }

      private static void updateSignature(Signature var0, ProtocolVersion var1, HandshakeHash var2, String var3, SecretKey var4) throws SignatureException {
         MessageDigest var5;
         if (var3.equals("RSA")) {
            if (var1.v < ProtocolVersion.TLS12.v) {
               var5 = var2.getMD5Clone();
               MessageDigest var6 = var2.getSHAClone();
               if (var1.v < ProtocolVersion.TLS10.v) {
                  updateDigest(var5, MD5_pad1, MD5_pad2, var4);
                  updateDigest(var6, SHA_pad1, SHA_pad2, var4);
               }

               RSASignature.setHashes(var0, var5, var6);
            } else {
               var0.update(var2.getAllHandshakeMessages());
            }
         } else if (var1.v < ProtocolVersion.TLS12.v) {
            var5 = null;
            if (var1.major == 1) {
               var5 = var2.getSM3Clone();
            } else {
               var5 = var2.getSHAClone();
               if (var1.v < ProtocolVersion.TLS10.v) {
                  updateDigest(var5, SHA_pad1, SHA_pad2, var4);
               }
            }

            var0.update(var5.digest());
         } else {
            var0.update(var2.getAllHandshakeMessages());
         }

      }

      private static void updateDigest(MessageDigest var0, byte[] var1, byte[] var2, SecretKey var3) {
         byte[] var4 = "RAW".equals(var3.getFormat()) ? var3.getEncoded() : null;
         if (var4 != null) {
            var0.update(var4);
         } else {
            digestKey(var0, var3);
         }

         var0.update(var1);
         byte[] var5 = var0.digest();
         if (var4 != null) {
            var0.update(var4);
         } else {
            digestKey(var0, var3);
         }

         var0.update(var2);
         var0.update(var5);
      }

      private static void makeAccessible(final AccessibleObject var0) {
         AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
               var0.setAccessible(true);
               return null;
            }
         });
      }

      private static void digestKey(MessageDigest var0, SecretKey var1) {
         try {
            if (var0.getClass() != delegate) {
               throw new Exception("Digest is not a MessageDigestSpi");
            } else {
               MessageDigestSpi var2 = (MessageDigestSpi)spiField.get(var0);
               Class var3 = var2.getClass();
               Object var4 = methodCache.get(var3);
               if (var4 == null) {
                  try {
                     var4 = var3.getDeclaredMethod("implUpdate", SecretKey.class);
                     makeAccessible((Method)var4);
                  } catch (NoSuchMethodException var6) {
                     var4 = NULL_OBJECT;
                  }

                  methodCache.put(var3, var4);
               }

               if (var4 == NULL_OBJECT) {
                  throw new Exception("Digest does not support implUpdate(SecretKey)");
               } else {
                  Method var5 = (Method)var4;
                  var5.invoke(var2, var1);
               }
            }
         } catch (Exception var7) {
            throw new RuntimeException("Could not obtain encoded key and MessageDigest cannot digest key", var7);
         }
      }

      int messageType() {
         return 15;
      }

      int messageLength() {
         int var1 = 2;
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            var1 += SignatureAndHashAlgorithm.sizeInRecord();
         }

         return var1 + this.signature.length;
      }

      void send(HandshakeOutStream var1) throws IOException {
         if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            var1.putInt8(this.preferableSignatureAlgorithm.getHashValue());
            var1.putInt8(this.preferableSignatureAlgorithm.getSignatureValue());
         }

         var1.putBytes16(this.signature);
      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** CertificateVerify");
         if (debug != null && Debug.isOn("verbose") && this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
            var1.println("Signature Algorithm " + this.preferableSignatureAlgorithm.getAlgorithmName());
         }

      }
   }

   static final class ClientHello extends HandshakeMessage {
      ProtocolVersion protocolVersion;
      RandomCookie clnt_random;
      SessionId sessionId;
      private CipherSuiteList cipherSuites;
      byte[] compression_methods;
      HelloExtensions extensions = new HelloExtensions();
      private static final byte[] NULL_COMPRESSION = new byte[1];

      ClientHello(SecureRandom var1, ProtocolVersion var2, SessionId var3, CipherSuiteList var4) {
         this.protocolVersion = var2;
         this.sessionId = var3;
         this.cipherSuites = var4;
         if (var4.containsEC()) {
            this.extensions.add(SupportedEllipticCurvesExtension.DEFAULT);
            this.extensions.add(SupportedEllipticPointFormatsExtension.DEFAULT);
         }

         this.clnt_random = new RandomCookie(var1);
         this.compression_methods = NULL_COMPRESSION;
      }

      ClientHello(HandshakeInStream var1, int var2) throws IOException {
         this.protocolVersion = ProtocolVersion.valueOf(var1.getInt8(), var1.getInt8());
         this.clnt_random = new RandomCookie(var1);
         this.sessionId = new SessionId(var1.getBytes8());
         this.cipherSuites = new CipherSuiteList(var1);
         this.compression_methods = var1.getBytes8();
         if (this.messageLength() != var2) {
            this.extensions = new HelloExtensions(var1);
         }

      }

      CipherSuiteList getCipherSuites() {
         return this.cipherSuites;
      }

      void addRenegotiationInfoExtension(byte[] var1) {
         RenegotiationInfoExtension var2 = new RenegotiationInfoExtension(var1, new byte[0]);
         this.extensions.add(var2);
      }

      void addServerNameIndicationExtension(String var1) {
         ArrayList var2 = new ArrayList(1);
         var2.add(var1);

         try {
            this.extensions.add(new ServerNameExtension(var2));
         } catch (IOException var4) {
            ;
         }

      }

      void addSignatureAlgorithmsExtension(Collection<SignatureAndHashAlgorithm> var1) {
         SignatureAlgorithmsExtension var2 = new SignatureAlgorithmsExtension(var1);
         this.extensions.add(var2);
      }

      int messageType() {
         return 1;
      }

      int messageLength() {
         return 38 + this.sessionId.length() + this.cipherSuites.size() * 2 + this.compression_methods.length + this.extensions.length();
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putInt8(this.protocolVersion.major);
         var1.putInt8(this.protocolVersion.minor);
         this.clnt_random.send(var1);
         var1.putBytes8(this.sessionId.getId());
         this.cipherSuites.send(var1);
         var1.putBytes8(this.compression_methods);
         this.extensions.send(var1);
      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** ClientHello, " + this.protocolVersion);
         if (debug != null && Debug.isOn("verbose")) {
            var1.print("RandomCookie:  ");
            this.clnt_random.print(var1);
            var1.print("Session ID:  ");
            var1.println(this.sessionId);
            var1.println("Cipher Suites: " + this.cipherSuites);
            Debug.println(var1, "Compression Methods", this.compression_methods);
            this.extensions.print(var1);
            var1.println("***");
         }

      }
   }

   static final class DH_ServerKeyExchange extends HandshakeMessage.ServerKeyExchange {
      private static final boolean dhKeyExchangeFix = Debug.getBooleanProperty("com.sun.net.ssl.dhKeyExchangeFix", true);
      private byte[] dh_p;
      private byte[] dh_g;
      private byte[] dh_Ys;
      private byte[] signature;
      ProtocolVersion protocolVersion;
      private SignatureAndHashAlgorithm preferableSignatureAlgorithm;

      DH_ServerKeyExchange(DHCrypt var1, ProtocolVersion var2) {
         this.protocolVersion = var2;
         this.preferableSignatureAlgorithm = null;
         this.setValues(var1);
         this.signature = null;
      }

      DH_ServerKeyExchange(DHCrypt var1, PrivateKey var2, byte[] var3, byte[] var4, SecureRandom var5, SignatureAndHashAlgorithm var6, ProtocolVersion var7) throws GeneralSecurityException {
         this.protocolVersion = var7;
         this.setValues(var1);
         Signature var8;
         if (var7.v >= ProtocolVersion.TLS12.v) {
            this.preferableSignatureAlgorithm = var6;
            var8 = JsseJce.getSignature(var6.getAlgorithmName());
         } else {
            this.preferableSignatureAlgorithm = null;
            if (var2.getAlgorithm().equals("DSA")) {
               var8 = JsseJce.getSignature("DSA");
            } else {
               var8 = RSASignature.getInstance();
            }
         }

         var8.initSign(var2, var5);
         this.updateSignature(var8, var3, var4);
         this.signature = var8.sign();
      }

      DH_ServerKeyExchange(HandshakeInStream var1, ProtocolVersion var2) throws IOException {
         this.protocolVersion = var2;
         this.preferableSignatureAlgorithm = null;
         this.dh_p = var1.getBytes16();
         this.dh_g = var1.getBytes16();
         this.dh_Ys = var1.getBytes16();
         this.signature = null;
      }

      DH_ServerKeyExchange(HandshakeInStream var1, PublicKey var2, byte[] var3, byte[] var4, int var5, Collection<SignatureAndHashAlgorithm> var6, ProtocolVersion var7) throws IOException, GeneralSecurityException {
         this.protocolVersion = var7;
         this.dh_p = var1.getBytes16();
         this.dh_g = var1.getBytes16();
         this.dh_Ys = var1.getBytes16();
         if (var7.v >= ProtocolVersion.TLS12.v) {
            int var8 = var1.getInt8();
            int var9 = var1.getInt8();
            this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.valueOf(var8, var9, 0);
            if (!var6.contains(this.preferableSignatureAlgorithm)) {
               throw new SSLHandshakeException("Unsupported SignatureAndHashAlgorithm in ServerKeyExchange message");
            }
         } else {
            this.preferableSignatureAlgorithm = null;
         }

         byte[] var11;
         if (dhKeyExchangeFix) {
            var11 = var1.getBytes16();
         } else {
            var5 -= this.dh_p.length + 2;
            var5 -= this.dh_g.length + 2;
            var5 -= this.dh_Ys.length + 2;
            var11 = new byte[var5];
            var1.read(var11);
         }

         String var10 = var2.getAlgorithm();
         Signature var12;
         if (var7.v >= ProtocolVersion.TLS12.v) {
            var12 = JsseJce.getSignature(this.preferableSignatureAlgorithm.getAlgorithmName());
         } else if (var10.equals("DSA")) {
            var12 = JsseJce.getSignature("DSA");
         } else {
            if (!var10.equals("RSA")) {
               throw new SSLKeyException("neither an RSA or a DSA key");
            }

            var12 = RSASignature.getInstance();
         }

         var12.initVerify(var2);
         this.updateSignature(var12, var3, var4);
         if (!var12.verify(var11)) {
            throw new SSLKeyException("Server D-H key verification failed");
         }
      }

      BigInteger getModulus() {
         return new BigInteger(1, this.dh_p);
      }

      BigInteger getBase() {
         return new BigInteger(1, this.dh_g);
      }

      BigInteger getServerPublicKey() {
         return new BigInteger(1, this.dh_Ys);
      }

      private void updateSignature(Signature var1, byte[] var2, byte[] var3) throws SignatureException {
         var1.update(var2);
         var1.update(var3);
         int var4 = this.dh_p.length;
         var1.update((byte)(var4 >> 8));
         var1.update((byte)(var4 & 255));
         var1.update(this.dh_p);
         var4 = this.dh_g.length;
         var1.update((byte)(var4 >> 8));
         var1.update((byte)(var4 & 255));
         var1.update(this.dh_g);
         var4 = this.dh_Ys.length;
         var1.update((byte)(var4 >> 8));
         var1.update((byte)(var4 & 255));
         var1.update(this.dh_Ys);
      }

      private void setValues(DHCrypt var1) {
         this.dh_p = toByteArray(var1.getModulus());
         this.dh_g = toByteArray(var1.getBase());
         this.dh_Ys = toByteArray(var1.getPublicKey());
      }

      int messageLength() {
         byte var1 = 6;
         int var2 = var1 + this.dh_p.length;
         var2 += this.dh_g.length;
         var2 += this.dh_Ys.length;
         if (this.signature != null) {
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var2 += SignatureAndHashAlgorithm.sizeInRecord();
            }

            var2 += this.signature.length;
            if (dhKeyExchangeFix) {
               var2 += 2;
            }
         }

         return var2;
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putBytes16(this.dh_p);
         var1.putBytes16(this.dh_g);
         var1.putBytes16(this.dh_Ys);
         if (this.signature != null) {
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var1.putInt8(this.preferableSignatureAlgorithm.getHashValue());
               var1.putInt8(this.preferableSignatureAlgorithm.getSignatureValue());
            }

            if (dhKeyExchangeFix) {
               var1.putBytes16(this.signature);
            } else {
               var1.write(this.signature);
            }
         }

      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** Diffie-Hellman ServerKeyExchange");
         if (debug != null && Debug.isOn("verbose")) {
            Debug.println(var1, "DH Modulus", this.dh_p);
            Debug.println(var1, "DH Base", this.dh_g);
            Debug.println(var1, "Server DH Public Key", this.dh_Ys);
            if (this.signature == null) {
               var1.println("Anonymous");
            } else {
               if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                  var1.println("Signature Algorithm " + this.preferableSignatureAlgorithm.getAlgorithmName());
               }

               var1.println("Signed with a DSA or RSA public key");
            }
         }

      }
   }

   static final class DistinguishedName {
      byte[] name;

      DistinguishedName(HandshakeInStream var1) throws IOException {
         this.name = var1.getBytes16();
      }

      DistinguishedName(X500Principal var1) {
         this.name = var1.getEncoded();
      }

      X500Principal getX500Principal() throws IOException {
         try {
            return new X500Principal(this.name);
         } catch (IllegalArgumentException var2) {
            throw (SSLProtocolException)(new SSLProtocolException(var2.getMessage())).initCause(var2);
         }
      }

      int length() {
         return 2 + this.name.length;
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putBytes16(this.name);
      }

      void print(PrintStream var1) throws IOException {
         X500Principal var2 = new X500Principal(this.name);
         var1.println("<" + var2.toString() + ">");
      }
   }

   static final class ECDH_ServerKeyExchange extends HandshakeMessage.ServerKeyExchange {
      private static final int CURVE_EXPLICIT_PRIME = 1;
      private static final int CURVE_EXPLICIT_CHAR2 = 2;
      private static final int CURVE_NAMED_CURVE = 3;
      private int curveId;
      private byte[] pointBytes;
      private byte[] signatureBytes;
      private ECPublicKey publicKey;
      ProtocolVersion protocolVersion;
      private SignatureAndHashAlgorithm preferableSignatureAlgorithm;

      ECDH_ServerKeyExchange(ECDHCrypt var1, PrivateKey var2, byte[] var3, byte[] var4, SecureRandom var5, SignatureAndHashAlgorithm var6, ProtocolVersion var7) throws GeneralSecurityException {
         this.protocolVersion = var7;
         this.publicKey = (ECPublicKey)var1.getPublicKey();
         ECParameterSpec var8 = this.publicKey.getParams();
         ECPoint var9 = this.publicKey.getW();
         this.pointBytes = JsseJce.encodePoint(var9, var8.getCurve());
         this.curveId = SupportedEllipticCurvesExtension.getCurveIndex(var8);
         if (var2 != null) {
            Signature var10;
            if (var7.v >= ProtocolVersion.TLS12.v) {
               this.preferableSignatureAlgorithm = var6;
               var10 = JsseJce.getSignature(var6.getAlgorithmName());
            } else {
               var10 = getSignature(var2.getAlgorithm());
            }

            var10.initSign(var2);
            this.updateSignature(var10, var3, var4);
            this.signatureBytes = var10.sign();
         }
      }

      ECDH_ServerKeyExchange(HandshakeInStream var1, PublicKey var2, byte[] var3, byte[] var4, Collection<SignatureAndHashAlgorithm> var5, ProtocolVersion var6) throws IOException, GeneralSecurityException {
         this.protocolVersion = var6;
         int var7 = var1.getInt8();
         if (var7 == 3) {
            this.curveId = var1.getInt16();
            if (!SupportedEllipticCurvesExtension.isSupported(this.curveId)) {
               throw new SSLHandshakeException("Unsupported curveId: " + this.curveId);
            } else {
               String var9 = SupportedEllipticCurvesExtension.getCurveOid(this.curveId);
               if (var9 == null) {
                  throw new SSLHandshakeException("Unknown named curve: " + this.curveId);
               } else {
                  ECParameterSpec var8 = JsseJce.getECParameterSpec(var9);
                  if (var8 == null) {
                     throw new SSLHandshakeException("Unsupported curve: " + var9);
                  } else {
                     this.pointBytes = var1.getBytes8();
                     ECPoint var14 = JsseJce.decodePoint(this.pointBytes, var8.getCurve());
                     KeyFactory var10 = JsseJce.getKeyFactory("EC");
                     this.publicKey = (ECPublicKey)var10.generatePublic(new ECPublicKeySpec(var14, var8));
                     if (var2 != null) {
                        if (var6.v >= ProtocolVersion.TLS12.v) {
                           int var11 = var1.getInt8();
                           int var12 = var1.getInt8();
                           this.preferableSignatureAlgorithm = SignatureAndHashAlgorithm.valueOf(var11, var12, 0);
                           if (!var5.contains(this.preferableSignatureAlgorithm)) {
                              throw new SSLHandshakeException("Unsupported SignatureAndHashAlgorithm in ServerKeyExchange message");
                           }
                        }

                        this.signatureBytes = var1.getBytes16();
                        Signature var13;
                        if (var6.v >= ProtocolVersion.TLS12.v) {
                           var13 = JsseJce.getSignature(this.preferableSignatureAlgorithm.getAlgorithmName());
                        } else {
                           var13 = getSignature(var2.getAlgorithm());
                        }

                        var13.initVerify(var2);
                        this.updateSignature(var13, var3, var4);
                        if (!var13.verify(this.signatureBytes)) {
                           throw new SSLKeyException("Invalid signature on ECDH server key exchange message");
                        }
                     }
                  }
               }
            }
         } else {
            throw new SSLHandshakeException("Unsupported ECCurveType: " + var7);
         }
      }

      ECPublicKey getPublicKey() {
         return this.publicKey;
      }

      private static Signature getSignature(String var0) throws NoSuchAlgorithmException {
         if (var0.equals("EC")) {
            return JsseJce.getSignature("SHA1withECDSA");
         } else if (var0.equals("RSA")) {
            return RSASignature.getInstance();
         } else {
            throw new NoSuchAlgorithmException("neither an RSA or a EC key");
         }
      }

      private void updateSignature(Signature var1, byte[] var2, byte[] var3) throws SignatureException {
         var1.update(var2);
         var1.update(var3);
         var1.update((byte)3);
         var1.update((byte)(this.curveId >> 8));
         var1.update((byte)this.curveId);
         var1.update((byte)this.pointBytes.length);
         var1.update(this.pointBytes);
      }

      int messageLength() {
         int var1 = 0;
         if (this.signatureBytes != null) {
            var1 = 2 + this.signatureBytes.length;
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var1 += SignatureAndHashAlgorithm.sizeInRecord();
            }
         }

         return 4 + this.pointBytes.length + var1;
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putInt8(3);
         var1.putInt16(this.curveId);
         var1.putBytes8(this.pointBytes);
         if (this.signatureBytes != null) {
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var1.putInt8(this.preferableSignatureAlgorithm.getHashValue());
               var1.putInt8(this.preferableSignatureAlgorithm.getSignatureValue());
            }

            var1.putBytes16(this.signatureBytes);
         }

      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** ECDH ServerKeyExchange");
         if (debug != null && Debug.isOn("verbose")) {
            if (this.signatureBytes == null) {
               var1.println("Anonymous");
            } else if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var1.println("Signature Algorithm " + this.preferableSignatureAlgorithm.getAlgorithmName());
            }

            var1.println("Server key: " + this.publicKey);
         }

      }
   }

   static final class Finished extends HandshakeMessage {
      static final int CLIENT = 1;
      static final int SERVER = 2;
      private static final byte[] SSL_CLIENT = new byte[]{67, 76, 78, 84};
      private static final byte[] SSL_SERVER = new byte[]{83, 82, 86, 82};
      private byte[] verifyData;
      private ProtocolVersion protocolVersion;
      private CipherSuite cipherSuite;

      Finished(ProtocolVersion var1, HandshakeHash var2, int var3, SecretKey var4, CipherSuite var5) {
         this.protocolVersion = var1;
         this.cipherSuite = var5;
         this.verifyData = this.getFinished(var2, var3, var4);
      }

      Finished(ProtocolVersion var1, HandshakeInStream var2, CipherSuite var3) throws IOException {
         this.protocolVersion = var1;
         this.cipherSuite = var3;
         int var4 = var1.v >= ProtocolVersion.TLS10.v ? 12 : 36;
         this.verifyData = new byte[var4];
         var2.read(this.verifyData);
      }

      boolean verify(HandshakeHash var1, int var2, SecretKey var3) {
         byte[] var4 = this.getFinished(var1, var2, var3);
         return Arrays.equals(var4, this.verifyData);
      }

      private byte[] getFinished(HandshakeHash var1, int var2, SecretKey var3) {
         byte[] var4;
         String var5;
         if (var2 == 1) {
            var4 = SSL_CLIENT;
            var5 = "client finished";
         } else {
            if (var2 != 2) {
               throw new RuntimeException("Invalid sender: " + var2);
            }

            var4 = SSL_SERVER;
            var5 = "server finished";
         }

         if (this.protocolVersion.v >= ProtocolVersion.TLS10.v) {
            try {
               byte[] var18;
               String var19;
               CipherSuite.PRF var20;
               if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
                  var18 = var1.getFinishedHash();
                  var19 = "SunTls12Prf";
                  var20 = this.cipherSuite.prfAlg;
               } else {
                  MessageDigest var9;
                  MessageDigest var10;
                  if (this.protocolVersion.major == 1) {
                     if (this.protocolVersion.minor == 0) {
                        var9 = var1.getSHAClone();
                        var10 = var1.getSM3Clone();
                        var18 = new byte[52];
                        var9.digest(var18, 0, 20);
                        var10.digest(var18, 20, 32);
                     } else {
                        if (this.protocolVersion.minor != 1) {
                           throw new RuntimeException("unsupported ssl version");
                        }

                        var9 = var1.getSM3Clone();
                        var18 = new byte[32];
                        var9.digest(var18, 0, 32);
                     }

                     var19 = "GBTlsPrf";
                  } else {
                     var9 = var1.getMD5Clone();
                     var10 = var1.getSHAClone();
                     var18 = new byte[36];
                     var9.digest(var18, 0, 16);
                     var10.digest(var18, 16, 20);
                     var19 = "SunTlsPrf";
                  }

                  var20 = CipherSuite.PRF.P_NONE;
               }

               String var21 = var20.getPRFHashAlg();
               int var22 = var20.getPRFHashLength();
               int var11 = var20.getPRFBlockSize();
               TlsPrfParameterSpec var12 = new TlsPrfParameterSpec(var3, var5, var18, 12, var21, var22, var11, this.protocolVersion);
               KeyGenerator var13 = JsseJce.getKeyGenerator(var19);
               var13.init(var12);
               SecretKey var14 = var13.generateKey();
               if (!"RAW".equals(var14.getFormat())) {
                  throw new ProviderException("Invalid PRF output, format must be RAW");
               } else {
                  byte[] var15 = var14.getEncoded();
                  return var15;
               }
            } catch (GeneralSecurityException var16) {
               throw new RuntimeException("PRF failed", var16);
            }
         } else {
            MessageDigest var6 = var1.getMD5Clone();
            MessageDigest var7 = var1.getSHAClone();
            updateDigest(var6, var4, MD5_pad1, MD5_pad2, var3);
            updateDigest(var7, var4, SHA_pad1, SHA_pad2, var3);
            byte[] var8 = new byte[36];

            try {
               var6.digest(var8, 0, 16);
               var7.digest(var8, 16, 20);
               return var8;
            } catch (DigestException var17) {
               throw new RuntimeException("Digest failed", var17);
            }
         }
      }

      private static void updateDigest(MessageDigest var0, byte[] var1, byte[] var2, byte[] var3, SecretKey var4) {
         var0.update(var1);
         HandshakeMessage.CertificateVerify.updateDigest(var0, var2, var3, var4);
      }

      byte[] getVerifyData() {
         return this.verifyData;
      }

      int messageType() {
         return 20;
      }

      int messageLength() {
         return this.verifyData.length;
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.write(this.verifyData);
      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** Finished");
         if (debug != null && Debug.isOn("verbose")) {
            Debug.println(var1, "verify_data", this.verifyData);
            var1.println("***");
         }

      }
   }

   static final class HelloRequest extends HandshakeMessage {
      int messageType() {
         return 0;
      }

      HelloRequest() {
      }

      HelloRequest(HandshakeInStream var1) throws IOException {
      }

      int messageLength() {
         return 0;
      }

      void send(HandshakeOutStream var1) throws IOException {
      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** HelloRequest (empty)");
      }
   }

   static final class RSA_ServerKeyExchange extends HandshakeMessage.ServerKeyExchange {
      private byte[] rsa_modulus;
      private byte[] rsa_exponent;
      private Signature signature;
      private byte[] signatureBytes;

      private void updateSignature(byte[] var1, byte[] var2) throws SignatureException {
         this.signature.update(var1);
         this.signature.update(var2);
         int var3 = this.rsa_modulus.length;
         this.signature.update((byte)(var3 >> 8));
         this.signature.update((byte)(var3 & 255));
         this.signature.update(this.rsa_modulus);
         var3 = this.rsa_exponent.length;
         this.signature.update((byte)(var3 >> 8));
         this.signature.update((byte)(var3 & 255));
         this.signature.update(this.rsa_exponent);
      }

      RSA_ServerKeyExchange(PublicKey var1, PrivateKey var2, RandomCookie var3, RandomCookie var4, SecureRandom var5) throws GeneralSecurityException {
         RSAPublicKeySpec var6 = JsseJce.getRSAPublicKeySpec(var1);
         this.rsa_modulus = toByteArray(var6.getModulus());
         this.rsa_exponent = toByteArray(var6.getPublicExponent());
         this.signature = RSASignature.getInstance();
         this.signature.initSign(var2, var5);
         this.updateSignature(var3.random_bytes, var4.random_bytes);
         this.signatureBytes = this.signature.sign();
      }

      RSA_ServerKeyExchange(HandshakeInStream var1) throws IOException, NoSuchAlgorithmException {
         this.signature = RSASignature.getInstance();
         this.rsa_modulus = var1.getBytes16();
         this.rsa_exponent = var1.getBytes16();
         this.signatureBytes = var1.getBytes16();
      }

      PublicKey getPublicKey() {
         try {
            KeyFactory var1 = JsseJce.getKeyFactory("RSA");
            RSAPublicKeySpec var2 = new RSAPublicKeySpec(new BigInteger(1, this.rsa_modulus), new BigInteger(1, this.rsa_exponent));
            return var1.generatePublic(var2);
         } catch (Exception var3) {
            throw new RuntimeException(var3);
         }
      }

      boolean verify(PublicKey var1, RandomCookie var2, RandomCookie var3) throws GeneralSecurityException {
         this.signature.initVerify(var1);
         this.updateSignature(var2.random_bytes, var3.random_bytes);
         return this.signature.verify(this.signatureBytes);
      }

      int messageLength() {
         return 6 + this.rsa_modulus.length + this.rsa_exponent.length + this.signatureBytes.length;
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putBytes16(this.rsa_modulus);
         var1.putBytes16(this.rsa_exponent);
         var1.putBytes16(this.signatureBytes);
      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** RSA ServerKeyExchange");
         if (debug != null && Debug.isOn("verbose")) {
            Debug.println(var1, "RSA Modulus", this.rsa_modulus);
            Debug.println(var1, "RSA Public Exponent", this.rsa_exponent);
         }

      }
   }

   static final class SM2_ServerKeyExchange extends HandshakeMessage.ServerKeyExchange {
      private static final int CURVE_EXPLICIT_PRIME = 1;
      private static final int CURVE_EXPLICIT_CHAR2 = 2;
      private static final int CURVE_NAMED_CURVE = 3;
      private int curveId;
      private byte[] pointBytes;
      private byte[] signatureBytes;
      private ECPublicKey publicKey;
      ProtocolVersion protocolVersion;
      private SignatureAndHashAlgorithm preferableSignatureAlgorithm;

      SM2_ServerKeyExchange(ECDHCrypt var1, PrivateKey var2, byte[] var3, byte[] var4, SecureRandom var5, SignatureAndHashAlgorithm var6, ProtocolVersion var7) throws GeneralSecurityException {
         this.protocolVersion = var7;
         this.publicKey = (ECPublicKey)var1.getPublicKey();
         ECParameterSpec var8 = this.publicKey.getParams();
         ECPoint var9 = this.publicKey.getW();
         this.pointBytes = JsseJce.encodePoint(var9, var8.getCurve());
         this.curveId = 23;
         if (var2 != null) {
            ;
         }
      }

      SM2_ServerKeyExchange(SM2Crypt var1, PrivateKey var2, byte[] var3, byte[] var4, SecureRandom var5, SignatureAndHashAlgorithm var6, ProtocolVersion var7, byte[] var8, PublicKey var9) throws GeneralSecurityException {
         this.protocolVersion = var7;
         this.pointBytes = var1.getRPointEncoded();
         this.curveId = 23;
         Signature var10 = SM2Util.sm2Sign(var2, var9);
         this.updateSignature(var10, var3, var4);
         if (var2 != null) {
            this.signatureBytes = var10.sign();
         }
      }

      SM2_ServerKeyExchange(HandshakeInStream var1, PublicKey var2, byte[] var3, byte[] var4, Collection<SignatureAndHashAlgorithm> var5, ProtocolVersion var6) throws IOException, GeneralSecurityException {
         this.protocolVersion = var6;
         int var7 = var1.getInt8();
         if (var7 == 3) {
            this.curveId = var1.getInt16();
            if (!SupportedEllipticCurvesExtension.isSupported(this.curveId)) {
               throw new SSLHandshakeException("Unsupported curveId: " + this.curveId);
            } else {
               String var9 = SupportedEllipticCurvesExtension.getCurveOid(this.curveId);
               if (var9 == null) {
                  throw new SSLHandshakeException("Unknown named curve: " + this.curveId);
               } else {
                  ECParameterSpec var8 = JsseJce.getECParameterSpec(var9);
                  if (var8 == null) {
                     throw new SSLHandshakeException("Unsupported curve: " + var9);
                  } else {
                     this.pointBytes = var1.getBytes8();
                     if (var6.minor == 0) {
                        ECPoint var15 = JsseJce.decodePoint(this.pointBytes, var8.getCurve());
                        KeyFactory var10 = JsseJce.getKeyFactory("EC");
                        this.publicKey = (ECPublicKey)var10.generatePublic(new ECPublicKeySpec(var15, var8));
                     } else {
                        org.bc.jce.spec.ECParameterSpec var16 = ((org.bc.jce.interfaces.ECPublicKey)var2).getParameters();
                        ECCurve var14 = var16.getCurve();
                        org.bc.math.ec.ECPoint var11 = var14.decodePoint(this.pointBytes);
                        KeyFactory var12 = KeyFactory.getInstance("ECDSA", "GMJCE");
                        org.bc.jce.spec.ECPublicKeySpec var13 = new org.bc.jce.spec.ECPublicKeySpec(var11, var16);
                        this.publicKey = (ECPublicKey)var12.generatePublic(var13);
                     }

                     this.signatureBytes = var1.getBytes16();
                     if (var2 != null) {
                        ;
                     }
                  }
               }
            }
         } else {
            throw new SSLHandshakeException("Unsupported ECCurveType: " + var7);
         }
      }

      ECPublicKey getPublicKey() {
         return this.publicKey;
      }

      int messageLength() {
         int var1 = 0;
         if (this.signatureBytes != null) {
            var1 = 2 + this.signatureBytes.length;
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var1 += SignatureAndHashAlgorithm.sizeInRecord();
            }
         }

         return 4 + this.pointBytes.length + var1;
      }

      private void updateSignature(Signature var1, byte[] var2, byte[] var3) throws SignatureException {
         var1.update(var2);
         var1.update(var3);
         var1.update((byte)3);
         var1.update((byte)(this.curveId >> 8));
         var1.update((byte)this.curveId);
         var1.update((byte)this.pointBytes.length);
         var1.update(this.pointBytes);
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putInt8(3);
         var1.putInt16(this.curveId);
         var1.putBytes8(this.pointBytes);
         if (this.signatureBytes != null) {
            if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var1.putInt8(this.preferableSignatureAlgorithm.getHashValue());
               var1.putInt8(this.preferableSignatureAlgorithm.getSignatureValue());
            }

            var1.putBytes16(this.signatureBytes);
         }

      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** ECDH ServerKeyExchange");
         if (debug != null && Debug.isOn("verbose")) {
            if (this.signatureBytes == null) {
               var1.println("Anonymous");
            } else if (this.protocolVersion.v >= ProtocolVersion.TLS12.v) {
               var1.println("Signature Algorithm " + this.preferableSignatureAlgorithm.getAlgorithmName());
            }

            var1.println("Server key: " + this.publicKey);
         }

      }
   }

   static final class ServerHello extends HandshakeMessage {
      ProtocolVersion protocolVersion;
      RandomCookie svr_random;
      SessionId sessionId;
      CipherSuite cipherSuite;
      byte compression_method;
      HelloExtensions extensions = new HelloExtensions();

      int messageType() {
         return 2;
      }

      ServerHello() {
      }

      ServerHello(HandshakeInStream var1, int var2) throws IOException {
         this.protocolVersion = ProtocolVersion.valueOf(var1.getInt8(), var1.getInt8());
         this.svr_random = new RandomCookie(var1);
         this.sessionId = new SessionId(var1.getBytes8());
         this.cipherSuite = CipherSuite.valueOf(var1.getInt8(), var1.getInt8());
         this.compression_method = (byte)var1.getInt8();
         if (this.messageLength() != var2) {
            this.extensions = new HelloExtensions(var1);
         }

      }

      int messageLength() {
         return 38 + this.sessionId.length() + this.extensions.length();
      }

      void send(HandshakeOutStream var1) throws IOException {
         var1.putInt8(this.protocolVersion.major);
         var1.putInt8(this.protocolVersion.minor);
         this.svr_random.send(var1);
         var1.putBytes8(this.sessionId.getId());
         var1.putInt8(this.cipherSuite.id >> 8);
         var1.putInt8(this.cipherSuite.id & 255);
         var1.putInt8(this.compression_method);
         this.extensions.send(var1);
      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** ServerHello, " + this.protocolVersion);
         if (debug != null && Debug.isOn("verbose")) {
            var1.print("RandomCookie:  ");
            this.svr_random.print(var1);
            var1.print("Session ID:  ");
            var1.println(this.sessionId);
            var1.println("Cipher Suite: " + this.cipherSuite);
            var1.println("Compression Method: " + this.compression_method);
            this.extensions.print(var1);
            var1.println("***");
         }

      }
   }

   static final class ServerHelloDone extends HandshakeMessage {
      int messageType() {
         return 14;
      }

      ServerHelloDone() {
      }

      ServerHelloDone(HandshakeInStream var1) {
      }

      int messageLength() {
         return 0;
      }

      void send(HandshakeOutStream var1) throws IOException {
      }

      void print(PrintStream var1) throws IOException {
         var1.println("*** ServerHelloDone");
      }
   }

   abstract static class ServerKeyExchange extends HandshakeMessage {
      int messageType() {
         return 12;
      }
   }
}
