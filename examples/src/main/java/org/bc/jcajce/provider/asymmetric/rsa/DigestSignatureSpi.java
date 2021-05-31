package org.bc.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERNull;
import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.oiw.OIWObjectIdentifiers;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.DigestInfo;
import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.Digest;
import org.bc.crypto.digests.MD2Digest;
import org.bc.crypto.digests.MD4Digest;
import org.bc.crypto.digests.MD5Digest;
import org.bc.crypto.digests.NullDigest;
import org.bc.crypto.digests.RIPEMD128Digest;
import org.bc.crypto.digests.RIPEMD160Digest;
import org.bc.crypto.digests.RIPEMD256Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA224Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA384Digest;
import org.bc.crypto.digests.SHA512Digest;
import org.bc.crypto.encodings.PKCS1Encoding;
import org.bc.crypto.engines.RSABlindedEngine;
import org.bc.crypto.params.RSAKeyParameters;

public class DigestSignatureSpi extends SignatureSpi {
   private Digest digest;
   private AsymmetricBlockCipher cipher;
   private AlgorithmIdentifier algId;

   protected DigestSignatureSpi(Digest var1, AsymmetricBlockCipher var2) {
      this.digest = var1;
      this.cipher = var2;
      this.algId = null;
   }

   protected DigestSignatureSpi(ASN1ObjectIdentifier var1, Digest var2, AsymmetricBlockCipher var3) {
      this.digest = var2;
      this.cipher = var3;
      this.algId = new AlgorithmIdentifier(var1, DERNull.INSTANCE);
   }

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      if (!(var1 instanceof RSAPublicKey)) {
         throw new InvalidKeyException("Supplied key (" + this.getType(var1) + ") is not a RSAPublicKey instance");
      } else {
         RSAKeyParameters var2 = RSAUtil.generatePublicKeyParameter((RSAPublicKey)var1);
         this.digest.reset();
         this.cipher.init(false, var2);
      }
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      if (!(var1 instanceof RSAPrivateKey)) {
         throw new InvalidKeyException("Supplied key (" + this.getType(var1) + ") is not a RSAPrivateKey instance");
      } else {
         RSAKeyParameters var2 = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)var1);
         this.digest.reset();
         this.cipher.init(true, var2);
      }
   }

   private String getType(Object var1) {
      return var1 == null ? null : var1.getClass().getName();
   }

   protected void engineUpdate(byte var1) throws SignatureException {
      this.digest.update(var1);
   }

   protected void engineUpdate(byte[] var1, int var2, int var3) throws SignatureException {
      this.digest.update(var1, var2, var3);
   }

   protected byte[] engineSign() throws SignatureException {
      byte[] var1 = new byte[this.digest.getDigestSize()];
      this.digest.doFinal(var1, 0);

      try {
         byte[] var2 = this.derEncode(var1);
         return this.cipher.processBlock(var2, 0, var2.length);
      } catch (ArrayIndexOutOfBoundsException var3) {
         throw new SignatureException("key too small for signature type");
      } catch (Exception var4) {
         throw new SignatureException(var4.toString());
      }
   }

   protected boolean engineVerify(byte[] var1) throws SignatureException {
      byte[] var2 = new byte[this.digest.getDigestSize()];
      this.digest.doFinal(var2, 0);

      byte[] var3;
      byte[] var4;
      try {
         var3 = this.cipher.processBlock(var1, 0, var1.length);
         var4 = this.derEncode(var2);
      } catch (Exception var8) {
         return false;
      }

      int var5;
      if (var3.length == var4.length) {
         for(var5 = 0; var5 < var3.length; ++var5) {
            if (var3[var5] != var4[var5]) {
               return false;
            }
         }
      } else {
         if (var3.length != var4.length - 2) {
            return false;
         }

         var5 = var3.length - var2.length - 2;
         int var6 = var4.length - var2.length - 2;
         var4[1] = (byte)(var4[1] - 2);
         var4[3] = (byte)(var4[3] - 2);

         int var7;
         for(var7 = 0; var7 < var2.length; ++var7) {
            if (var3[var5 + var7] != var4[var6 + var7]) {
               return false;
            }
         }

         for(var7 = 0; var7 < var5; ++var7) {
            if (var3[var7] != var4[var7]) {
               return false;
            }
         }
      }

      return true;
   }

   protected void engineSetParameter(AlgorithmParameterSpec var1) {
      throw new UnsupportedOperationException("engineSetParameter unsupported");
   }

   /** @deprecated */
   protected void engineSetParameter(String var1, Object var2) {
      throw new UnsupportedOperationException("engineSetParameter unsupported");
   }

   /** @deprecated */
   protected Object engineGetParameter(String var1) {
      return null;
   }

   protected AlgorithmParameters engineGetParameters() {
      return null;
   }

   private byte[] derEncode(byte[] var1) throws IOException {
      if (this.algId == null) {
         return var1;
      } else {
         DigestInfo var2 = new DigestInfo(this.algId, var1);
         return var2.getEncoded("DER");
      }
   }

   public static class MD2 extends DigestSignatureSpi {
      public MD2() {
         super(PKCSObjectIdentifiers.md2, new MD2Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class MD4 extends DigestSignatureSpi {
      public MD4() {
         super(PKCSObjectIdentifiers.md4, new MD4Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class MD5 extends DigestSignatureSpi {
      public MD5() {
         super(PKCSObjectIdentifiers.md5, new MD5Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class RIPEMD128 extends DigestSignatureSpi {
      public RIPEMD128() {
         super(TeleTrusTObjectIdentifiers.ripemd128, new RIPEMD128Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class RIPEMD160 extends DigestSignatureSpi {
      public RIPEMD160() {
         super(TeleTrusTObjectIdentifiers.ripemd160, new RIPEMD160Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class RIPEMD256 extends DigestSignatureSpi {
      public RIPEMD256() {
         super(TeleTrusTObjectIdentifiers.ripemd256, new RIPEMD256Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class SHA1 extends DigestSignatureSpi {
      public SHA1() {
         super(OIWObjectIdentifiers.idSHA1, new SHA1Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class SHA224 extends DigestSignatureSpi {
      public SHA224() {
         super(NISTObjectIdentifiers.id_sha224, new SHA224Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class SHA256 extends DigestSignatureSpi {
      public SHA256() {
         super(NISTObjectIdentifiers.id_sha256, new SHA256Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class SHA384 extends DigestSignatureSpi {
      public SHA384() {
         super(NISTObjectIdentifiers.id_sha384, new SHA384Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class SHA512 extends DigestSignatureSpi {
      public SHA512() {
         super(NISTObjectIdentifiers.id_sha512, new SHA512Digest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }

   public static class noneRSA extends DigestSignatureSpi {
      public noneRSA() {
         super(new NullDigest(), new PKCS1Encoding(new RSABlindedEngine()));
      }
   }
}
