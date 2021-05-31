package cn.gmssl.crypto.util;

import cn.gmssl.crypto.impl.sm2.SM2Util;
import java.math.BigInteger;
import java.security.SecureRandom;

public class FixRandom extends SecureRandom {
   private BigInteger random = null;

   public FixRandom(BigInteger var1) {
      this.random = var1;
   }

   public synchronized void nextBytes(byte[] var1) {
      byte[] var2 = SM2Util.intToBytes(this.random);
      if (var1.length != var2.length) {
         throw new RuntimeException("invalid random length");
      } else {
         System.arraycopy(var2, 0, var1, 0, var1.length);
      }
   }
}
