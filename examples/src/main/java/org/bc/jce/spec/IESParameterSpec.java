package org.bc.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class IESParameterSpec implements AlgorithmParameterSpec {
   private byte[] derivation;
   private byte[] encoding;
   private int macKeySize;
   private int cipherKeySize;

   public IESParameterSpec(byte[] var1, byte[] var2, int var3) {
      this(var1, var2, var3, -1);
   }

   public IESParameterSpec(byte[] var1, byte[] var2, int var3, int var4) {
      if (var1 != null) {
         this.derivation = new byte[var1.length];
         System.arraycopy(var1, 0, this.derivation, 0, var1.length);
      } else {
         this.derivation = null;
      }

      if (var2 != null) {
         this.encoding = new byte[var2.length];
         System.arraycopy(var2, 0, this.encoding, 0, var2.length);
      } else {
         this.encoding = null;
      }

      this.macKeySize = var3;
      this.cipherKeySize = var4;
   }

   public byte[] getDerivationV() {
      return this.derivation;
   }

   public byte[] getEncodingV() {
      return this.encoding;
   }

   public int getMacKeySize() {
      return this.macKeySize;
   }

   public int getCipherKeySize() {
      return this.cipherKeySize;
   }
}
