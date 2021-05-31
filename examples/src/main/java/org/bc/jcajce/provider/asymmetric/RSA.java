package org.bc.jcajce.provider.asymmetric;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.asn1.x509.X509ObjectIdentifiers;
import org.bc.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import org.bc.jcajce.provider.config.ConfigurableProvider;
import org.bc.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class RSA {
   private static final String PREFIX = "org.bc.jcajce.provider.asymmetric.rsa.";

   public static class Mappings extends AsymmetricAlgorithmProvider {
      public void configure(ConfigurableProvider var1) {
         var1.addAlgorithm("AlgorithmParameters.OAEP", "org.bc.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi$OAEP");
         var1.addAlgorithm("AlgorithmParameters.PSS", "org.bc.jcajce.provider.asymmetric.rsa.AlgorithmParametersSpi$PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.RSAPSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.RSASSA-PSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224withRSA/PSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256withRSA/PSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384withRSA/PSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512withRSA/PSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224WITHRSAANDMGF1", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256WITHRSAANDMGF1", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384WITHRSAANDMGF1", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512WITHRSAANDMGF1", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.RAWRSAPSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAPSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSASSA-PSS", "PSS");
         var1.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAANDMGF1", "PSS");
         var1.addAlgorithm("Cipher.RSA", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$NoPadding");
         var1.addAlgorithm("Cipher.RSA/RAW", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$NoPadding");
         var1.addAlgorithm("Cipher.RSA/PKCS1", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding");
         var1.addAlgorithm("Cipher.1.2.840.113549.1.1.1", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding");
         var1.addAlgorithm("Cipher.2.5.8.1.1", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding");
         var1.addAlgorithm("Cipher.RSA/1", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding_PrivateOnly");
         var1.addAlgorithm("Cipher.RSA/2", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$PKCS1v1_5Padding_PublicOnly");
         var1.addAlgorithm("Cipher.RSA/OAEP", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$OAEPPadding");
         var1.addAlgorithm("Cipher." + PKCSObjectIdentifiers.id_RSAES_OAEP, "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$OAEPPadding");
         var1.addAlgorithm("Cipher.RSA/ISO9796-1", "org.bc.jcajce.provider.asymmetric.rsa.CipherSpi$ISO9796d1Padding");
         var1.addAlgorithm("Alg.Alias.Cipher.RSA//RAW", "RSA");
         var1.addAlgorithm("Alg.Alias.Cipher.RSA//NOPADDING", "RSA");
         var1.addAlgorithm("Alg.Alias.Cipher.RSA//PKCS1PADDING", "RSA/PKCS1");
         var1.addAlgorithm("Alg.Alias.Cipher.RSA//OAEPPADDING", "RSA/OAEP");
         var1.addAlgorithm("Alg.Alias.Cipher.RSA//ISO9796-1PADDING", "RSA/ISO9796-1");
         var1.addAlgorithm("KeyFactory.RSA", "org.bc.jcajce.provider.asymmetric.rsa.KeyFactorySpi");
         var1.addAlgorithm("KeyPairGenerator.RSA", "org.bc.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi");
         KeyFactorySpi var2 = new KeyFactorySpi();
         this.registerOid(var1, PKCSObjectIdentifiers.rsaEncryption, "RSA", var2);
         this.registerOid(var1, X509ObjectIdentifiers.id_ea_rsa, "RSA", var2);
         this.registerOid(var1, PKCSObjectIdentifiers.id_RSAES_OAEP, "RSA", var2);
         this.registerOid(var1, PKCSObjectIdentifiers.id_RSASSA_PSS, "RSA", var2);
         this.registerOidAlgorithmParameters(var1, PKCSObjectIdentifiers.rsaEncryption, "RSA");
         this.registerOidAlgorithmParameters(var1, X509ObjectIdentifiers.id_ea_rsa, "RSA");
         this.registerOidAlgorithmParameters(var1, PKCSObjectIdentifiers.id_RSAES_OAEP, "OAEP");
         this.registerOidAlgorithmParameters(var1, PKCSObjectIdentifiers.id_RSASSA_PSS, "PSS");
         var1.addAlgorithm("Signature.RSASSA-PSS", "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$PSSwithRSA");
         var1.addAlgorithm("Signature." + PKCSObjectIdentifiers.id_RSASSA_PSS, "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$PSSwithRSA");
         var1.addAlgorithm("Signature.OID." + PKCSObjectIdentifiers.id_RSASSA_PSS, "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$PSSwithRSA");
         var1.addAlgorithm("Signature.SHA224withRSA/PSS", "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA224withRSA");
         var1.addAlgorithm("Signature.SHA256withRSA/PSS", "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA256withRSA");
         var1.addAlgorithm("Signature.SHA384withRSA/PSS", "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA384withRSA");
         var1.addAlgorithm("Signature.SHA512withRSA/PSS", "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA512withRSA");
         var1.addAlgorithm("Signature.RSA", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$noneRSA");
         var1.addAlgorithm("Signature.RAWRSASSA-PSS", "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$nonePSS");
         var1.addAlgorithm("Alg.Alias.Signature.RAWRSA", "RSA");
         var1.addAlgorithm("Alg.Alias.Signature.NONEWITHRSA", "RSA");
         var1.addAlgorithm("Alg.Alias.Signature.RAWRSAPSS", "RAWRSASSA-PSS");
         var1.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAPSS", "RAWRSASSA-PSS");
         var1.addAlgorithm("Alg.Alias.Signature.NONEWITHRSASSA-PSS", "RAWRSASSA-PSS");
         var1.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAANDMGF1", "RAWRSASSA-PSS");
         var1.addAlgorithm("Alg.Alias.Signature.RSAPSS", "RSASSA-PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA224withRSAandMGF1", "SHA224withRSA/PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA256withRSAandMGF1", "SHA256withRSA/PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA384withRSAandMGF1", "SHA384withRSA/PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA512withRSAandMGF1", "SHA512withRSA/PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA224WITHRSAANDMGF1", "SHA224withRSA/PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA256WITHRSAANDMGF1", "SHA256withRSA/PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA384WITHRSAANDMGF1", "SHA384withRSA/PSS");
         var1.addAlgorithm("Alg.Alias.Signature.SHA512WITHRSAANDMGF1", "SHA512withRSA/PSS");
         if (var1.hasAlgorithm("MessageDigest", "MD2")) {
            this.addDigestSignature(var1, "MD2", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD2", PKCSObjectIdentifiers.md2WithRSAEncryption);
         }

         if (var1.hasAlgorithm("MessageDigest", "MD4")) {
            this.addDigestSignature(var1, "MD4", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD4", PKCSObjectIdentifiers.md4WithRSAEncryption);
         }

         if (var1.hasAlgorithm("MessageDigest", "MD5")) {
            this.addDigestSignature(var1, "MD5", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$MD5", PKCSObjectIdentifiers.md5WithRSAEncryption);
            var1.addAlgorithm("Signature.MD5withRSA/ISO9796-2", "org.bc.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$MD5WithRSAEncryption");
            var1.addAlgorithm("Alg.Alias.Signature.MD5WithRSA/ISO9796-2", "MD5withRSA/ISO9796-2");
         }

         if (var1.hasAlgorithm("MessageDigest", "SHA1")) {
            var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1withRSA/PSS", "PSS");
            var1.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1WITHRSAANDMGF1", "PSS");
            var1.addAlgorithm("Signature.SHA1withRSA/PSS", "org.bc.jcajce.provider.asymmetric.rsa.PSSSignatureSpi$SHA1withRSA");
            var1.addAlgorithm("Alg.Alias.Signature.SHA1withRSAandMGF1", "SHA1withRSA/PSS");
            var1.addAlgorithm("Alg.Alias.Signature.SHA1WITHRSAANDMGF1", "SHA1withRSA/PSS");
            this.addDigestSignature(var1, "SHA1", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA1", PKCSObjectIdentifiers.sha1WithRSAEncryption);
            var1.addAlgorithm("Alg.Alias.Signature.SHA1WithRSA/ISO9796-2", "SHA1withRSA/ISO9796-2");
            var1.addAlgorithm("Signature.SHA1withRSA/ISO9796-2", "org.bc.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$SHA1WithRSAEncryption");
            var1.addAlgorithm("Alg.Alias.Signature." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
            var1.addAlgorithm("Alg.Alias.Signature.OID." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
         }

         this.addDigestSignature(var1, "SHA224", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA224", PKCSObjectIdentifiers.sha224WithRSAEncryption);
         this.addDigestSignature(var1, "SHA256", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA256", PKCSObjectIdentifiers.sha256WithRSAEncryption);
         this.addDigestSignature(var1, "SHA384", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA384", PKCSObjectIdentifiers.sha384WithRSAEncryption);
         this.addDigestSignature(var1, "SHA512", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$SHA512", PKCSObjectIdentifiers.sha512WithRSAEncryption);
         if (var1.hasAlgorithm("MessageDigest", "RIPEMD128")) {
            this.addDigestSignature(var1, "RIPEMD128", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
            this.addDigestSignature(var1, "RMD128", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD128", (ASN1ObjectIdentifier)null);
         }

         if (var1.hasAlgorithm("MessageDigest", "RIPEMD160")) {
            this.addDigestSignature(var1, "RIPEMD160", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
            this.addDigestSignature(var1, "RMD160", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD160", (ASN1ObjectIdentifier)null);
            var1.addAlgorithm("Alg.Alias.Signature.RIPEMD160WithRSA/ISO9796-2", "RIPEMD160withRSA/ISO9796-2");
            var1.addAlgorithm("Signature.RIPEMD160withRSA/ISO9796-2", "org.bc.jcajce.provider.asymmetric.rsa.ISOSignatureSpi$RIPEMD160WithRSAEncryption");
         }

         if (var1.hasAlgorithm("MessageDigest", "RIPEMD256")) {
            this.addDigestSignature(var1, "RIPEMD256", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
            this.addDigestSignature(var1, "RMD256", "org.bc.jcajce.provider.asymmetric.rsa.DigestSignatureSpi$RIPEMD256", (ASN1ObjectIdentifier)null);
         }

      }

      private void addDigestSignature(ConfigurableProvider var1, String var2, String var3, ASN1ObjectIdentifier var4) {
         String var5 = var2 + "WITHRSA";
         String var6 = var2 + "withRSA";
         String var7 = var2 + "WithRSA";
         String var8 = var2 + "/" + "RSA";
         String var9 = var2 + "WITHRSAENCRYPTION";
         String var10 = var2 + "withRSAEncryption";
         String var11 = var2 + "WithRSAEncryption";
         var1.addAlgorithm("Signature." + var5, var3);
         var1.addAlgorithm("Alg.Alias.Signature." + var6, var5);
         var1.addAlgorithm("Alg.Alias.Signature." + var7, var5);
         var1.addAlgorithm("Alg.Alias.Signature." + var9, var5);
         var1.addAlgorithm("Alg.Alias.Signature." + var10, var5);
         var1.addAlgorithm("Alg.Alias.Signature." + var11, var5);
         var1.addAlgorithm("Alg.Alias.Signature." + var8, var5);
         if (var4 != null) {
            var1.addAlgorithm("Alg.Alias.Signature." + var4, var5);
            var1.addAlgorithm("Alg.Alias.Signature.OID." + var4, var5);
         }

      }
   }
}
