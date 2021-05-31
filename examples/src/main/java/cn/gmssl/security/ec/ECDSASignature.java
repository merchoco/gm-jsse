package cn.gmssl.security.ec;

import cn.gmssl.security.util.DerInputStream;
import cn.gmssl.security.util.DerOutputStream;
import cn.gmssl.security.util.DerValue;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import sun.security.jca.JCAUtil;

abstract class ECDSASignature extends SignatureSpi {
   private final MessageDigest messageDigest;
   private SecureRandom random;
   private boolean needsReset;
   private ECPrivateKey privateKey;
   private ECPublicKey publicKey;

   ECDSASignature() {
      this.messageDigest = null;
   }

   ECDSASignature(String var1) {
      try {
         this.messageDigest = MessageDigest.getInstance(var1);
      } catch (NoSuchAlgorithmException var3) {
         throw new ProviderException(var3);
      }

      this.needsReset = false;
   }

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      this.publicKey = (ECPublicKey)ECKeyFactory.toECKey(var1);
      this.privateKey = null;
      this.resetDigest();
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      this.engineInitSign(var1, (SecureRandom)null);
   }

   protected void engineInitSign(PrivateKey var1, SecureRandom var2) throws InvalidKeyException {
      this.privateKey = (ECPrivateKey)ECKeyFactory.toECKey(var1);
      this.publicKey = null;
      this.random = var2;
      this.resetDigest();
   }

   protected void resetDigest() {
      if (this.needsReset) {
         if (this.messageDigest != null) {
            this.messageDigest.reset();
         }

         this.needsReset = false;
      }

   }

   protected byte[] getDigestValue() throws SignatureException {
      this.needsReset = false;
      return this.messageDigest.digest();
   }

   protected void engineUpdate(byte var1) throws SignatureException {
      this.messageDigest.update(var1);
      this.needsReset = true;
   }

   protected void engineUpdate(byte[] var1, int var2, int var3) throws SignatureException {
      this.messageDigest.update(var1, var2, var3);
      this.needsReset = true;
   }

   protected void engineUpdate(ByteBuffer var1) {
      int var2 = var1.remaining();
      if (var2 > 0) {
         this.messageDigest.update(var1);
         this.needsReset = true;
      }
   }

   protected byte[] engineSign() throws SignatureException {
      byte[] var1 = this.privateKey.getS().toByteArray();
      ECParameterSpec var2 = this.privateKey.getParams();
      byte[] var3 = ECParameters.encodeParameters(var2);
      int var4 = var2.getCurve().getField().getFieldSize();
      byte[] var5 = new byte[((var4 + 7 >> 3) + 1) * 2];
      if (this.random == null) {
         this.random = JCAUtil.getSecureRandom();
      }

      this.random.nextBytes(var5);

      try {
         return this.encodeSignature(signDigest(this.getDigestValue(), var1, var3, var5));
      } catch (GeneralSecurityException var7) {
         throw new SignatureException("Could not sign data", var7);
      }
   }

   protected boolean engineVerify(byte[] var1) throws SignatureException {
      ECParameterSpec var3 = this.publicKey.getParams();
      byte[] var4 = ECParameters.encodeParameters(var3);
      byte[] var2;
      if (this.publicKey instanceof ECPublicKeyImpl) {
         var2 = ((ECPublicKeyImpl)this.publicKey).getEncodedPublicValue();
      } else {
         var2 = ECParameters.encodePoint(this.publicKey.getW(), var3.getCurve());
      }

      try {
         return verifySignedDigest(this.decodeSignature(var1), this.getDigestValue(), var2, var4);
      } catch (GeneralSecurityException var6) {
         throw new SignatureException("Could not verify signature", var6);
      }
   }

   protected void engineSetParameter(String var1, Object var2) throws InvalidParameterException {
      throw new UnsupportedOperationException("setParameter() not supported");
   }

   protected Object engineGetParameter(String var1) throws InvalidParameterException {
      throw new UnsupportedOperationException("getParameter() not supported");
   }

   private byte[] encodeSignature(byte[] var1) throws SignatureException {
      try {
         int var2 = var1.length >> 1;
         byte[] var3 = new byte[var2];
         System.arraycopy(var1, 0, var3, 0, var2);
         BigInteger var4 = new BigInteger(1, var3);
         System.arraycopy(var1, var2, var3, 0, var2);
         BigInteger var5 = new BigInteger(1, var3);
         DerOutputStream var6 = new DerOutputStream(var1.length + 10);
         var6.putInteger(var4);
         var6.putInteger(var5);
         DerValue var7 = new DerValue((byte)48, var6.toByteArray());
         var6.close();
         return var7.toByteArray();
      } catch (Exception var8) {
         throw new SignatureException("Could not encode signature", var8);
      }
   }

   private byte[] decodeSignature(byte[] var1) throws SignatureException {
      try {
         DerInputStream var2 = new DerInputStream(var1);
         DerValue[] var3 = var2.getSequence(2);
         BigInteger var4 = var3[0].getPositiveBigInteger();
         BigInteger var5 = var3[1].getPositiveBigInteger();
         byte[] var6 = trimZeroes(var4.toByteArray());
         byte[] var7 = trimZeroes(var5.toByteArray());
         int var8 = Math.max(var6.length, var7.length);
         byte[] var9 = new byte[var8 << 1];
         System.arraycopy(var6, 0, var9, var8 - var6.length, var6.length);
         System.arraycopy(var7, 0, var9, var9.length - var7.length, var7.length);
         return var9;
      } catch (Exception var10) {
         throw new SignatureException("Could not decode signature", var10);
      }
   }

   private static byte[] trimZeroes(byte[] var0) {
      int var1;
      for(var1 = 0; var1 < var0.length - 1 && var0[var1] == 0; ++var1) {
         ;
      }

      if (var1 == 0) {
         return var0;
      } else {
         byte[] var2 = new byte[var0.length - var1];
         System.arraycopy(var0, var1, var2, 0, var2.length);
         return var2;
      }
   }

   private static native byte[] signDigest(byte[] var0, byte[] var1, byte[] var2, byte[] var3) throws GeneralSecurityException;

   private static native boolean verifySignedDigest(byte[] var0, byte[] var1, byte[] var2, byte[] var3) throws GeneralSecurityException;

   public static final class Raw extends ECDSASignature {
      private static final int RAW_ECDSA_MAX = 64;
      private final byte[] precomputedDigest = new byte[64];
      private int offset = 0;

      protected void engineUpdate(byte var1) throws SignatureException {
         if (this.offset >= this.precomputedDigest.length) {
            this.offset = 65;
         } else {
            this.precomputedDigest[this.offset++] = var1;
         }
      }

      protected void engineUpdate(byte[] var1, int var2, int var3) throws SignatureException {
         if (this.offset >= this.precomputedDigest.length) {
            this.offset = 65;
         } else {
            System.arraycopy(var1, var2, this.precomputedDigest, this.offset, var3);
            this.offset += var3;
         }
      }

      protected void engineUpdate(ByteBuffer var1) {
         int var2 = var1.remaining();
         if (var2 > 0) {
            if (this.offset + var2 >= this.precomputedDigest.length) {
               this.offset = 65;
            } else {
               var1.get(this.precomputedDigest, this.offset, var2);
               this.offset += var2;
            }
         }
      }

      protected void resetDigest() {
         this.offset = 0;
      }

      protected byte[] getDigestValue() throws SignatureException {
         if (this.offset > 64) {
            throw new SignatureException("Message digest is too long");
         } else {
            byte[] var1 = new byte[this.offset];
            System.arraycopy(this.precomputedDigest, 0, var1, 0, this.offset);
            this.offset = 0;
            return var1;
         }
      }
   }

   public static final class SHA1 extends ECDSASignature {
      public SHA1() {
         super("SHA1");
      }
   }

   public static final class SHA256 extends ECDSASignature {
      public SHA256() {
         super("SHA-256");
      }
   }

   public static final class SHA384 extends ECDSASignature {
      public SHA384() {
         super("SHA-384");
      }
   }

   public static final class SHA512 extends ECDSASignature {
      public SHA512() {
         super("SHA-512");
      }
   }
}
