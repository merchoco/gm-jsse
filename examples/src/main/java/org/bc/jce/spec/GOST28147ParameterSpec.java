package org.bc.jce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bc.crypto.engines.GOST28147Engine;

public class GOST28147ParameterSpec implements AlgorithmParameterSpec {
   private byte[] iv;
   private byte[] sBox;

   public GOST28147ParameterSpec(byte[] var1) {
      this.iv = null;
      this.sBox = null;
      this.sBox = new byte[var1.length];
      System.arraycopy(var1, 0, this.sBox, 0, var1.length);
   }

   public GOST28147ParameterSpec(byte[] var1, byte[] var2) {
      this(var1);
      this.iv = new byte[var2.length];
      System.arraycopy(var2, 0, this.iv, 0, var2.length);
   }

   public GOST28147ParameterSpec(String var1) {
      this.iv = null;
      this.sBox = null;
      this.sBox = GOST28147Engine.getSBox(var1);
   }

   public GOST28147ParameterSpec(String var1, byte[] var2) {
      this(var1);
      this.iv = new byte[var2.length];
      System.arraycopy(var2, 0, this.iv, 0, var2.length);
   }

   public byte[] getSbox() {
      return this.sBox;
   }

   public byte[] getIV() {
      if (this.iv == null) {
         return null;
      } else {
         byte[] var1 = new byte[this.iv.length];
         System.arraycopy(this.iv, 0, var1, 0, var1.length);
         return var1;
      }
   }
}
