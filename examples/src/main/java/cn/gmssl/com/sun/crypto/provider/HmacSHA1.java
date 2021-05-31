package cn.gmssl.com.sun.crypto.provider;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;

public final class HmacSHA1 extends MacSpi implements Cloneable {
   private HmacCore hmac = null;
   private static final int SHA1_BLOCK_LENGTH = 64;

   public HmacSHA1() throws NoSuchAlgorithmException {
      this.hmac = new HmacCore(MessageDigest.getInstance("SHA1"), 64);
   }

   protected int engineGetMacLength() {
      return this.hmac.getDigestLength();
   }

   protected void engineInit(Key var1, AlgorithmParameterSpec var2) throws InvalidKeyException, InvalidAlgorithmParameterException {
      this.hmac.init(var1, var2);
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
      HmacSHA1 var1 = null;

      try {
         var1 = (HmacSHA1)super.clone();
         var1.hmac = (HmacCore)this.hmac.clone();
      } catch (CloneNotSupportedException var3) {
         ;
      }

      return var1;
   }
}
