package org.bc.crypto.modes.gcm;

import org.bc.util.Arrays;

public class BasicGCMMultiplier implements GCMMultiplier {
   private byte[] H;

   public void init(byte[] var1) {
      this.H = Arrays.clone(var1);
   }

   public void multiplyH(byte[] var1) {
      GCMUtil.multiply(var1, this.H);
   }
}
