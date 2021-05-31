package cn.gmssl.crypto.impl;

import cn.gmssl.crypto.util.Debug;
import cn.gmssl.crypto.util.PrintUtil;
import org.bc.crypto.digests.GeneralDigest;
import org.bc.crypto.util.Pack;

public class SM3 extends GeneralDigest {
   private static final int DIGEST_LENGTH = 32;
   private int H1;
   private int H2;
   private int H3;
   private int H4;
   private int H5;
   private int H6;
   private int H7;
   private int H8;
   private int[] word = new int[68];
   private int wordOff;

   public SM3() {
      this.reset();
   }

   protected void processBlock() {
      if (Debug.sm3) {
         PrintUtil.printHex((int[])this.word, 0, 16, "block");
      }

      for(int var1 = 16; var1 <= 67; ++var1) {
         this.word[var1] = this.P1(this.word[var1 - 16] ^ this.word[var1 - 9] ^ this.cycleShiftLeft(this.word[var1 - 3], 15)) ^ this.cycleShiftLeft(this.word[var1 - 13], 7) ^ this.word[var1 - 6];
      }

      if (Debug.sm3) {
         PrintUtil.printHex(this.word, "W:");
      }

      int[] var15 = new int[64];

      int var2;
      for(var2 = 0; var2 <= 63; ++var2) {
         var15[var2] = this.word[var2] ^ this.word[var2 + 4];
      }

      if (Debug.sm3) {
         PrintUtil.printHex(var15, "W':");
      }

      var2 = this.H1;
      int var3 = this.H2;
      int var4 = this.H3;
      int var5 = this.H4;
      int var6 = this.H5;
      int var7 = this.H6;
      int var8 = this.H7;
      int var9 = this.H8;

      int var10;
      for(var10 = 0; var10 < 64; ++var10) {
         int var11 = this.cycleShiftLeft(this.cycleShiftLeft(var2, 12) + var6 + this.cycleShiftLeft(this.T(var10), var10), 7);
         int var12 = var11 ^ this.cycleShiftLeft(var2, 12);
         int var13 = this.FF(var2, var3, var4, var10) + var5 + var12 + var15[var10];
         int var14 = this.GG(var6, var7, var8, var10) + var9 + var11 + this.word[var10];
         var5 = var4;
         var4 = this.cycleShiftLeft(var3, 9);
         var3 = var2;
         var2 = var13;
         var9 = var8;
         var8 = this.cycleShiftLeft(var7, 19);
         var7 = var6;
         var6 = this.P0(var14);
         if (Debug.sm3) {
            this.printIter(var10, var13, var3, var4, var5, var6, var7, var8, var9);
         }
      }

      this.H1 ^= var2;
      this.H2 ^= var3;
      this.H3 ^= var4;
      this.H4 ^= var5;
      this.H5 ^= var6;
      this.H6 ^= var7;
      this.H7 ^= var8;
      this.H8 ^= var9;
      this.wordOff = 0;

      for(var10 = 0; var10 != this.word.length; ++var10) {
         this.word[var10] = 0;
      }

   }

   protected void processLength(long var1) {
      if (this.wordOff > 14) {
         this.processBlock();
      }

      this.word[14] = (int)(var1 >>> 32);
      this.word[15] = (int)(var1 & -1L);
   }

   protected void processWord(byte[] var1, int var2) {
      int var3 = var1[var2] << 24;
      ++var2;
      var3 |= (var1[var2] & 255) << 16;
      ++var2;
      var3 |= (var1[var2] & 255) << 8;
      ++var2;
      var3 |= var1[var2] & 255;
      this.word[this.wordOff] = var3;
      if (++this.wordOff == 16) {
         this.processBlock();
      }

   }

   public int doFinal(byte[] var1, int var2) {
      this.finish();
      Pack.intToBigEndian(this.H1, var1, var2);
      Pack.intToBigEndian(this.H2, var1, var2 + 4);
      Pack.intToBigEndian(this.H3, var1, var2 + 8);
      Pack.intToBigEndian(this.H4, var1, var2 + 12);
      Pack.intToBigEndian(this.H5, var1, var2 + 16);
      Pack.intToBigEndian(this.H6, var1, var2 + 20);
      Pack.intToBigEndian(this.H7, var1, var2 + 24);
      Pack.intToBigEndian(this.H8, var1, var2 + 28);
      this.reset();
      return 32;
   }

   public String getAlgorithmName() {
      return "SM3";
   }

   public int getDigestSize() {
      return 32;
   }

   public void reset() {
      super.reset();
      this.H1 = 1937774191;
      this.H2 = 1226093241;
      this.H3 = 388252375;
      this.H4 = -628488704;
      this.H5 = -1452330820;
      this.H6 = 372324522;
      this.H7 = -477237683;
      this.H8 = -1325724082;
      this.wordOff = 0;

      for(int var1 = 0; var1 != this.word.length; ++var1) {
         this.word[var1] = 0;
      }

   }

   public int FF(int var1, int var2, int var3, int var4) {
      if (var4 >= 0 && var4 <= 15) {
         return var1 ^ var2 ^ var3;
      } else if (var4 >= 16 && var4 <= 63) {
         return var1 & var2 | var1 & var3 | var2 & var3;
      } else {
         throw new RuntimeException("索引越界");
      }
   }

   public int GG(int var1, int var2, int var3, int var4) {
      if (var4 >= 0 && var4 <= 15) {
         return var1 ^ var2 ^ var3;
      } else if (var4 >= 16 && var4 <= 63) {
         return var1 & var2 | ~var1 & var3;
      } else {
         throw new RuntimeException("索引越界");
      }
   }

   public int P0(int var1) {
      return var1 ^ this.cycleShiftLeft(var1, 9) ^ this.cycleShiftLeft(var1, 17);
   }

   public int P1(int var1) {
      return var1 ^ this.cycleShiftLeft(var1, 15) ^ this.cycleShiftLeft(var1, 23);
   }

   public int T(int var1) {
      if (var1 >= 0 && var1 <= 15) {
         return 2043430169;
      } else if (var1 >= 16 && var1 <= 63) {
         return 2055708042;
      } else {
         throw new RuntimeException("索引越界：" + var1);
      }
   }

   private int cycleShiftLeft(int var1, int var2) {
      return var1 << var2 | var1 >>> 32 - var2;
   }

   private void printIter(int var1, int var2, int var3, int var4, int var5, int var6, int var7, int var8, int var9) {
      String var10 = "" + var1;
      if (var10.length() == 1) {
         var10 = "0" + var10;
      }

      System.out.print(var10 + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var2)) + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var3)) + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var4)) + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var5)) + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var6)) + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var7)) + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var8)) + " ");
      System.out.print(PrintUtil.padString(Integer.toHexString(var9)) + " ");
      System.out.println();
   }
}
