package cn.gmssl.com.sun.crypto.provider;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class HmacPKCS12PBESHA1 extends MacSpi implements Cloneable {
   private HmacCore hmac = null;
   private static final int SHA1_BLOCK_LENGTH = 64;

   public HmacPKCS12PBESHA1() throws NoSuchAlgorithmException {
      this.hmac = new HmacCore(MessageDigest.getInstance("SHA1"), 64);
   }

   protected int engineGetMacLength() {
      return this.hmac.getDigestLength();
   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
      byte[] var4 = null;
      int var5 = 0;
      char[] var3;
      byte[] var6;
      if (var1 instanceof javax.crypto.interfaces.PBEKey) {
         javax.crypto.interfaces.PBEKey var8 = (javax.crypto.interfaces.PBEKey)var1;
         var3 = var8.getPassword();
         var4 = var8.getSalt();
         var5 = var8.getIterationCount();
      } else {
         if (!(var1 instanceof SecretKey)) {
            throw new InvalidKeyException("SecretKey of PBE type required");
         }

         var6 = var1.getEncoded();
         if (var6 == null || !var1.getAlgorithm().regionMatches(true, 0, "PBE", 0, 3)) {
            throw new InvalidKeyException("Missing password");
         }

         var3 = new char[var6.length];

         for(int var7 = 0; var7 < var3.length; ++var7) {
            var3[var7] = (char)(var6[var7] & 127);
         }
      }

      if (var2 == null) {
         if (var4 == null) {
            var4 = new byte[20];
            SunJCE.RANDOM.nextBytes(var4);
         }

         if (var5 == 0) {
            var5 = 100;
         }
      } else {
         if (!(var2 instanceof PBEParameterSpec)) {
            throw new InvalidAlgorithmParameterException("PBEParameterSpec type required");
         }

         PBEParameterSpec var9 = (PBEParameterSpec)var2;
         if (var4 != null) {
            if (!Arrays.equals(var4, var9.getSalt())) {
               throw new InvalidAlgorithmParameterException("Inconsistent value of salt between key and params");
            }
         } else {
            var4 = var9.getSalt();
         }

         if (var5 != 0) {
            if (var5 != var9.getIterationCount()) {
               throw new InvalidAlgorithmParameterException("Different iteration count between key and params");
            }
         } else {
            var5 = var9.getIterationCount();
         }
      }

      if (var4.length < 8) {
         throw new InvalidAlgorithmParameterException("Salt must be at least 8 bytes long");
      } else if (var5 <= 0) {
         throw new InvalidAlgorithmParameterException("IterationCount must be a positive number");
      } else {
         var6 = PKCS12PBECipherCore.derive(var3, var4, var5, this.hmac.getDigestLength(), 3);
         SecretKeySpec var10 = new SecretKeySpec(var6, "HmacSHA1");
         this.hmac.init(var10, (AlgorithmParameterSpec)null);
      }
   }

   protected void engineUpdate(byte var1) {
      this.hmac.update(var1);
   }

   protected void engineUpdate(byte[] var1, int var2, int var3) {
      this.hmac.update(var1, var2, var3);
   }

   protected void engineUpdate(ByteBuffer var1) {
      this.hmac.update(var1);
   }

   protected byte[] engineDoFinal() {
      return this.hmac.doFinal();
   }

   protected void engineReset() {
      this.hmac.reset();
   }

   public Object clone() {
      HmacPKCS12PBESHA1 var1 = null;

      try {
         var1 = (HmacPKCS12PBESHA1)super.clone();
         var1.hmac = (HmacCore)this.hmac.clone();
      } catch (CloneNotSupportedException var3) {
         ;
      }

      return var1;
   }
}
