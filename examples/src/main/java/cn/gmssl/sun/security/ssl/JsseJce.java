package cn.gmssl.sun.security.ssl;

import cn.gmssl.com.sun.crypto.provider.SunJCE;
import cn.gmssl.security.ec.ECParameters;
import cn.gmssl.security.ec.NamedCurve;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AccessController;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.Provider.Service;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;
import java.util.Map.Entry;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

final class JsseJce {
   private static final Debug debug = Debug.getInstance("ssl");
   private static final ProviderList fipsProviderList;
   private static Boolean ecAvailable;
   private static final boolean kerberosAvailable;
   static final String CIPHER_RSA_PKCS1 = "RSA/ECB/PKCS1Padding";
   static final String CIPHER_RC4 = "RC4";
   static final String CIPHER_DES = "DES/CBC/NoPadding";
   static final String CIPHER_3DES = "DESede/CBC/NoPadding";
   static final String CIPHER_AES = "AES/CBC/NoPadding";
   static final String SIGNATURE_DSA = "DSA";
   static final String SIGNATURE_ECDSA = "SHA1withECDSA";
   static final String SIGNATURE_RAWDSA = "RawDSA";
   static final String SIGNATURE_RAWECDSA = "NONEwithECDSA";
   static final String SIGNATURE_RAWRSA = "NONEwithRSA";
   static final String SIGNATURE_SSLRSA = "MD5andSHA1withRSA";

   static {
      boolean var0;
      try {
         AccessController.doPrivileged(new PrivilegedExceptionAction<Void>() {
            public Void run() throws Exception {
               Class.forName("sun.security.krb5.PrincipalName", true, (ClassLoader)null);
               return null;
            }
         });
         var0 = true;
      } catch (Exception var2) {
         var0 = false;
      }

      kerberosAvailable = var0;
      if (!MyJSSE.isFIPS()) {
         fipsProviderList = null;
      } else {
         Provider var3 = Security.getProvider("SUN");
         if (var3 == null) {
            throw new RuntimeException("FIPS mode: SUN provider must be installed");
         }

         JsseJce.SunCertificates var1 = new JsseJce.SunCertificates(var3);
         fipsProviderList = ProviderList.newList(MyJSSE.cryptoProvider, var1);
      }

   }

   static synchronized boolean isEcAvailable() {
      if (ecAvailable == null) {
         try {
            getSignature("SHA1withECDSA");
            getSignature("NONEwithECDSA");
            getKeyAgreement("ECDH");
            getKeyFactory("EC");
            getKeyPairGenerator("EC");
            ecAvailable = true;
         } catch (Exception var1) {
            ecAvailable = false;
         }
      }

      return ecAvailable;
   }

   static synchronized void clearEcAvailable() {
      ecAvailable = null;
   }

   static boolean isKerberosAvailable() {
      return kerberosAvailable;
   }

   static Cipher getCipher(String var0) throws NoSuchAlgorithmException {
      try {
         if ("RSA/ECB/PKCS1Padding".equals(var0)) {
            return Cipher.getInstance(var0, new SunJCE());
         } else {
            return MyJSSE.cryptoProvider == null ? Cipher.getInstance(var0) : Cipher.getInstance(var0, MyJSSE.cryptoProvider);
         }
      } catch (NoSuchPaddingException var2) {
         throw new NoSuchAlgorithmException(var2);
      }
   }

   static Signature getSignature(String var0) throws NoSuchAlgorithmException {
      if (MyJSSE.cryptoProvider == null) {
         return Signature.getInstance(var0);
      } else if (var0 == "MD5andSHA1withRSA" && MyJSSE.cryptoProvider.getService("Signature", var0) == null) {
         try {
            return Signature.getInstance(var0, "SunJSSE");
         } catch (NoSuchProviderException var2) {
            throw new NoSuchAlgorithmException(var2);
         }
      } else {
         return Signature.getInstance(var0, MyJSSE.cryptoProvider);
      }
   }

   static KeyGenerator getKeyGenerator(String var0) throws NoSuchAlgorithmException {
      return MyJSSE.cryptoProvider == null ? KeyGenerator.getInstance(var0) : KeyGenerator.getInstance(var0, MyJSSE.cryptoProvider);
   }

   static KeyPairGenerator getKeyPairGenerator(String var0) throws NoSuchAlgorithmException {
      return MyJSSE.cryptoProvider == null ? KeyPairGenerator.getInstance(var0) : KeyPairGenerator.getInstance(var0, MyJSSE.cryptoProvider);
   }

   static KeyAgreement getKeyAgreement(String var0) throws NoSuchAlgorithmException {
      return MyJSSE.cryptoProvider == null ? KeyAgreement.getInstance(var0) : KeyAgreement.getInstance(var0, MyJSSE.cryptoProvider);
   }

   static Mac getMac(String var0) throws NoSuchAlgorithmException {
      return MyJSSE.cryptoProvider == null ? Mac.getInstance(var0) : Mac.getInstance(var0, MyJSSE.cryptoProvider);
   }

   static KeyFactory getKeyFactory(String var0) throws NoSuchAlgorithmException {
      return MyJSSE.cryptoProvider == null ? KeyFactory.getInstance(var0) : KeyFactory.getInstance(var0, MyJSSE.cryptoProvider);
   }

   static SecureRandom getSecureRandom() throws KeyManagementException {
      if (MyJSSE.cryptoProvider == null) {
         return new SecureRandom();
      } else {
         try {
            return SecureRandom.getInstance("PKCS11", MyJSSE.cryptoProvider);
         } catch (NoSuchAlgorithmException var4) {
            Iterator var1 = MyJSSE.cryptoProvider.getServices().iterator();

            while(true) {
               Service var0;
               do {
                  if (!var1.hasNext()) {
                     throw new KeyManagementException("FIPS mode: no SecureRandom  implementation found in provider " + MyJSSE.cryptoProvider.getName());
                  }

                  var0 = (Service)var1.next();
               } while(!var0.getType().equals("SecureRandom"));

               try {
                  return SecureRandom.getInstance(var0.getAlgorithm(), MyJSSE.cryptoProvider);
               } catch (NoSuchAlgorithmException var3) {
                  ;
               }
            }
         }
      }
   }

   static MessageDigest getMD5() {
      try {
         return getMessageDigest("MD5");
      } catch (Exception var1) {
         var1.printStackTrace();
         return null;
      }
   }

   static MessageDigest getSHA() {
      try {
         return getMessageDigest("SHA");
      } catch (Exception var1) {
         var1.printStackTrace();
         return null;
      }
   }

   static MessageDigest getMessageDigest(String var0) throws NoSuchAlgorithmException {
      try {
         return MyJSSE.cryptoProvider == null ? MessageDigest.getInstance(var0) : MessageDigest.getInstance(var0, MyJSSE.cryptoProvider);
      } catch (NoSuchAlgorithmException var2) {
         throw var2;
      }
   }

   static int getRSAKeyLength(PublicKey var0) {
      BigInteger var1;
      if (var0 instanceof RSAPublicKey) {
         var1 = ((RSAPublicKey)var0).getModulus();
      } else {
         RSAPublicKeySpec var2 = getRSAPublicKeySpec(var0);
         var1 = var2.getModulus();
      }

      return var1.bitLength();
   }

   static RSAPublicKeySpec getRSAPublicKeySpec(PublicKey var0) {
      if (var0 instanceof RSAPublicKey) {
         RSAPublicKey var3 = (RSAPublicKey)var0;
         return new RSAPublicKeySpec(var3.getModulus(), var3.getPublicExponent());
      } else {
         try {
            KeyFactory var1 = getKeyFactory("RSA");
            return (RSAPublicKeySpec)var1.getKeySpec(var0, RSAPublicKeySpec.class);
         } catch (Exception var2) {
            throw (RuntimeException)(new RuntimeException()).initCause(var2);
         }
      }
   }

   static ECParameterSpec getECParameterSpec(String var0) {
      return NamedCurve.getECParameterSpec(var0);
   }

   static String getNamedCurveOid(ECParameterSpec var0) {
      return ECParameters.getCurveName(var0);
   }

   static ECPoint decodePoint(byte[] var0, EllipticCurve var1) throws IOException {
      return ECParameters.decodePoint(var0, var1);
   }

   static byte[] encodePoint(ECPoint var0, EllipticCurve var1) {
      return ECParameters.encodePoint(var0, var1);
   }

   static Object beginFipsProvider() {
      return fipsProviderList == null ? null : Providers.beginThreadProviderList(fipsProviderList);
   }

   static void endFipsProvider(Object var0) {
      if (fipsProviderList != null) {
         Providers.endThreadProviderList((ProviderList)var0);
      }

   }

   private static final class SunCertificates extends Provider {
      SunCertificates(final Provider var1) {
         super("SunCertificates", 1.0D, "SunJSSE internal");
         AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
               Iterator var2 = var1.entrySet().iterator();

               while(true) {
                  Entry var1x;
                  String var3;
                  do {
                     if (!var2.hasNext()) {
                        return null;
                     }

                     var1x = (Entry)var2.next();
                     var3 = (String)var1x.getKey();
                  } while(!var3.startsWith("CertPathValidator.") && !var3.startsWith("CertPathBuilder.") && !var3.startsWith("CertStore.") && !var3.startsWith("CertificateFactory."));

                  SunCertificates.this.put(var3, var1x.getValue());
               }
            }
         });
      }
   }
}
