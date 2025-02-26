package org.bc.pqc.crypto.gmss.util;

import org.bc.crypto.Digest;

public class GMSSRandom {
   private Digest messDigestTree;

   public GMSSRandom(Digest var1) {
      this.messDigestTree = var1;
   }

   public byte[] nextSeed(byte[] var1) {
      byte[] var2 = new byte[var1.length];
      this.messDigestTree.update(var1, 0, var1.length);
      var2 = new byte[this.messDigestTree.getDigestSize()];
      this.messDigestTree.doFinal(var2, 0);
      this.addByteArrays(var1, var2);
      this.addOne(var1);
      return var2;
   }

   private void addByteArrays(byte[] var1, byte[] var2) {
      byte var3 = 0;

      for(int var5 = 0; var5 < var1.length; ++var5) {
         int var4 = (255 & var1[var5]) + (255 & var2[var5]) + var3;
         var1[var5] = (byte)var4;
         var3 = (byte)(var4 >> 8);
      }

   }

   private void addOne(byte[] var1) {
      byte var2 = 1;

      for(int var4 = 0; var4 < var1.length; ++var4) {
         int var3 = (255 & var1[var4]) + var2;
         var1[var4] = (byte)var3;
         var2 = (byte)(var3 >> 8);
      }

   }
}
