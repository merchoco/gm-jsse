package org.bc.ocsp;

import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Set;
import org.bc.asn1.DERNull;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.util.Strings;

class OCSPUtil {
   private static Hashtable algorithms = new Hashtable();
   private static Hashtable oids = new Hashtable();
   private static Set noParams = new HashSet();

   static {
      algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption);
      algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption);
      algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption);
      algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption);
      algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption);
      algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption);
      algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
      algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
      algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
      algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
      algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
      algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
      algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
      algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
      algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
      algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
      algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
      algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
      algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
      algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
      algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1);
      algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1);
      algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224);
      algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256);
      algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
      algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1);
      algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
      algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
      algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
      algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
      algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
      algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
      oids.put(PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2WITHRSA");
      oids.put(PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5WITHRSA");
      oids.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1WITHRSA");
      oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
      oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
      oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
      oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
      oids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160WITHRSA");
      oids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128WITHRSA");
      oids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256WITHRSA");
      oids.put(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1WITHDSA");
      oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
      oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
      oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
      oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
      oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
      oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
      oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
      oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
      noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA1);
      noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA224);
      noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
      noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA384);
      noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA512);
      noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1);
      noParams.add(NISTObjectIdentifiers.dsa_with_sha224);
      noParams.add(NISTObjectIdentifiers.dsa_with_sha256);
   }

   static DERObjectIdentifier getAlgorithmOID(String var0) {
      var0 = Strings.toUpperCase(var0);
      return algorithms.containsKey(var0) ? (DERObjectIdentifier)algorithms.get(var0) : new DERObjectIdentifier(var0);
   }

   static String getAlgorithmName(DERObjectIdentifier var0) {
      return oids.containsKey(var0) ? (String)oids.get(var0) : var0.getId();
   }

   static AlgorithmIdentifier getSigAlgID(DERObjectIdentifier var0) {
      return noParams.contains(var0) ? new AlgorithmIdentifier(var0) : new AlgorithmIdentifier(var0, DERNull.INSTANCE);
   }

   static Iterator getAlgNames() {
      Enumeration var0 = algorithms.keys();
      ArrayList var1 = new ArrayList();

      while(var0.hasMoreElements()) {
         var1.add(var0.nextElement());
      }

      return var1.iterator();
   }

   static CertStore createCertStoreInstance(String var0, CertStoreParameters var1, String var2) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
      return var2 == null ? CertStore.getInstance(var0, var1) : CertStore.getInstance(var0, var1, var2);
   }

   static MessageDigest createDigestInstance(String var0, String var1) throws NoSuchAlgorithmException, NoSuchProviderException {
      return var1 == null ? MessageDigest.getInstance(var0) : MessageDigest.getInstance(var0, var1);
   }

   static Signature createSignatureInstance(String var0, String var1) throws NoSuchAlgorithmException, NoSuchProviderException {
      return var1 == null ? Signature.getInstance(var0) : Signature.getInstance(var0, var1);
   }

   static CertificateFactory createX509CertificateFactory(String var0) throws CertificateException, NoSuchProviderException {
      return var0 == null ? CertificateFactory.getInstance("X.509") : CertificateFactory.getInstance("X.509", var0);
   }
}
