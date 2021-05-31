package org.bc.crypto.params;

import org.bc.crypto.CipherParameters;

public class RC2Parameters implements CipherParameters {
   private byte[] key;
   private int bits;

   public RC2Parameters(byte[] var1) {
      this(var1, var1.length > 128 ? 1024 : var1.length * 8);
   }

   public RC2Parameters(byte[] var1, int var2) {
      this.key = new byte[var1.length];
      this.bits = var2;
      System.arraycopy(var1, 0, this.key, 0, var1.length);
   }

   public byte[] getKey() {
      return this.key;
   }

   public int getEffectiveKeyBits() {
      return this.bits;
   }
}
