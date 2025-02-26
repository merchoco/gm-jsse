package org.bc.crypto.engines;

import java.util.Hashtable;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithSBox;
import org.bc.util.Arrays;
import org.bc.util.Strings;

public class GOST28147Engine implements BlockCipher {
   protected static final int BLOCK_SIZE = 8;
   private int[] workingKey = null;
   private boolean forEncryption;
   private byte[] S;
   private static byte[] Sbox_Default = new byte[]{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3, 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9, 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11, 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3, 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2, 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14, 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12, 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12};
   private static byte[] ESbox_Test = new byte[]{4, 2, 15, 5, 9, 1, 0, 8, 14, 3, 11, 12, 13, 7, 10, 6, 12, 9, 15, 14, 8, 1, 3, 10, 2, 7, 4, 13, 6, 0, 11, 5, 13, 8, 14, 12, 7, 3, 9, 10, 1, 5, 2, 4, 6, 15, 0, 11, 14, 9, 11, 2, 5, 15, 7, 1, 0, 13, 12, 6, 10, 4, 3, 8, 3, 14, 5, 9, 6, 8, 0, 13, 10, 11, 7, 12, 2, 1, 15, 4, 8, 15, 6, 11, 1, 9, 12, 5, 13, 3, 7, 10, 0, 14, 2, 4, 9, 11, 12, 0, 3, 6, 7, 5, 4, 8, 14, 15, 1, 10, 2, 13, 12, 6, 5, 2, 11, 0, 9, 13, 3, 14, 7, 10, 15, 4, 1, 8};
   private static byte[] ESbox_A = new byte[]{9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5, 3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1, 14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9, 14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6, 11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6, 3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6, 1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14, 11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4};
   private static byte[] ESbox_B = new byte[]{8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15, 0, 1, 2, 10, 4, 13, 5, 12, 9, 7, 3, 15, 11, 8, 6, 14, 14, 12, 0, 10, 9, 2, 13, 11, 7, 5, 8, 15, 3, 6, 1, 4, 7, 5, 0, 13, 11, 6, 1, 2, 3, 10, 12, 15, 4, 14, 9, 8, 2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3, 8, 3, 2, 6, 4, 13, 14, 11, 12, 1, 7, 15, 10, 0, 9, 5, 5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14, 0, 4, 11, 14, 8, 3, 7, 1, 10, 2, 9, 6, 15, 13, 5, 12};
   private static byte[] ESbox_C = new byte[]{1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3, 0, 1, 7, 13, 11, 4, 5, 2, 8, 14, 15, 12, 9, 10, 6, 3, 8, 2, 5, 0, 4, 9, 15, 10, 3, 7, 12, 13, 6, 14, 1, 11, 3, 6, 0, 1, 5, 13, 10, 8, 11, 2, 9, 7, 14, 15, 12, 4, 8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7, 12, 9, 11, 1, 8, 14, 2, 4, 7, 3, 6, 5, 10, 0, 15, 13, 10, 9, 6, 8, 13, 14, 2, 0, 15, 3, 5, 11, 4, 1, 12, 7, 7, 4, 0, 5, 10, 2, 15, 14, 12, 6, 1, 11, 13, 9, 3, 8};
   private static byte[] ESbox_D = new byte[]{15, 12, 2, 10, 6, 4, 5, 0, 7, 9, 14, 13, 1, 11, 8, 3, 11, 6, 3, 4, 12, 15, 14, 2, 7, 13, 8, 0, 5, 10, 9, 1, 1, 12, 11, 0, 15, 14, 6, 5, 10, 13, 4, 8, 9, 3, 7, 2, 1, 5, 14, 12, 10, 7, 0, 13, 6, 2, 11, 4, 9, 3, 15, 8, 0, 12, 8, 9, 13, 2, 10, 11, 7, 3, 6, 5, 4, 14, 15, 1, 8, 0, 15, 3, 2, 5, 14, 11, 1, 10, 4, 7, 12, 9, 13, 6, 3, 0, 6, 15, 1, 14, 9, 2, 13, 8, 12, 4, 11, 10, 5, 7, 1, 10, 6, 8, 15, 11, 0, 4, 12, 3, 5, 9, 7, 13, 2, 14};
   private static byte[] DSbox_Test = new byte[]{4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3, 14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9, 5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11, 7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3, 6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2, 4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14, 13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12, 1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12};
   private static byte[] DSbox_A = new byte[]{10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15, 5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8, 7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13, 4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3, 7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5, 7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3, 13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11, 1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12};
   private static Hashtable sBoxes = new Hashtable();

   static {
      addSBox("Default", Sbox_Default);
      addSBox("E-TEST", ESbox_Test);
      addSBox("E-A", ESbox_A);
      addSBox("E-B", ESbox_B);
      addSBox("E-C", ESbox_C);
      addSBox("E-D", ESbox_D);
      addSBox("D-TEST", DSbox_Test);
      addSBox("D-A", DSbox_A);
   }

   private static void addSBox(String var0, byte[] var1) {
      sBoxes.put(Strings.toUpperCase(var0), var1);
   }

   public GOST28147Engine() {
      this.S = Sbox_Default;
   }

   public void init(boolean var1, CipherParameters var2) {
      if (var2 instanceof ParametersWithSBox) {
         ParametersWithSBox var3 = (ParametersWithSBox)var2;
         byte[] var4 = var3.getSBox();
         if (var4.length != Sbox_Default.length) {
            throw new IllegalArgumentException("invalid S-box passed to GOST28147 init");
         }

         this.S = Arrays.clone(var4);
         if (var3.getParameters() != null) {
            this.workingKey = this.generateWorkingKey(var1, ((KeyParameter)var3.getParameters()).getKey());
         }
      } else if (var2 instanceof KeyParameter) {
         this.workingKey = this.generateWorkingKey(var1, ((KeyParameter)var2).getKey());
      } else if (var2 != null) {
         throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + var2.getClass().getName());
      }

   }

   public String getAlgorithmName() {
      return "GOST28147";
   }

   public int getBlockSize() {
      return 8;
   }

   public int processBlock(byte[] var1, int var2, byte[] var3, int var4) {
      if (this.workingKey == null) {
         throw new IllegalStateException("GOST28147 engine not initialised");
      } else if (var2 + 8 > var1.length) {
         throw new DataLengthException("input buffer too short");
      } else if (var4 + 8 > var3.length) {
         throw new DataLengthException("output buffer too short");
      } else {
         this.GOST28147Func(this.workingKey, var1, var2, var3, var4);
         return 8;
      }
   }

   public void reset() {
   }

   private int[] generateWorkingKey(boolean var1, byte[] var2) {
      this.forEncryption = var1;
      if (var2.length != 32) {
         throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
      } else {
         int[] var3 = new int[8];

         for(int var4 = 0; var4 != 8; ++var4) {
            var3[var4] = this.bytesToint(var2, var4 * 4);
         }

         return var3;
      }
   }

   private int GOST28147_mainStep(int var1, int var2) {
      int var3 = var2 + var1;
      int var4 = this.S[0 + (var3 >> 0 & 15)] << 0;
      var4 += this.S[16 + (var3 >> 4 & 15)] << 4;
      var4 += this.S[32 + (var3 >> 8 & 15)] << 8;
      var4 += this.S[48 + (var3 >> 12 & 15)] << 12;
      var4 += this.S[64 + (var3 >> 16 & 15)] << 16;
      var4 += this.S[80 + (var3 >> 20 & 15)] << 20;
      var4 += this.S[96 + (var3 >> 24 & 15)] << 24;
      var4 += this.S[112 + (var3 >> 28 & 15)] << 28;
      return var4 << 11 | var4 >>> 21;
   }

   private void GOST28147Func(int[] var1, byte[] var2, int var3, byte[] var4, int var5) {
      int var6 = this.bytesToint(var2, var3);
      int var7 = this.bytesToint(var2, var3 + 4);
      int var8;
      int var9;
      int var10;
      if (this.forEncryption) {
         for(var9 = 0; var9 < 3; ++var9) {
            for(var10 = 0; var10 < 8; ++var10) {
               var8 = var6;
               var6 = var7 ^ this.GOST28147_mainStep(var6, var1[var10]);
               var7 = var8;
            }
         }

         for(var9 = 7; var9 > 0; --var9) {
            var8 = var6;
            var6 = var7 ^ this.GOST28147_mainStep(var6, var1[var9]);
            var7 = var8;
         }
      } else {
         for(var9 = 0; var9 < 8; ++var9) {
            var8 = var6;
            var6 = var7 ^ this.GOST28147_mainStep(var6, var1[var9]);
            var7 = var8;
         }

         for(var9 = 0; var9 < 3; ++var9) {
            for(var10 = 7; var10 >= 0 && (var9 != 2 || var10 != 0); --var10) {
               var8 = var6;
               var6 = var7 ^ this.GOST28147_mainStep(var6, var1[var10]);
               var7 = var8;
            }
         }
      }

      var7 ^= this.GOST28147_mainStep(var6, var1[0]);
      this.intTobytes(var6, var4, var5);
      this.intTobytes(var7, var4, var5 + 4);
   }

   private int bytesToint(byte[] var1, int var2) {
      return (var1[var2 + 3] << 24 & -16777216) + (var1[var2 + 2] << 16 & 16711680) + (var1[var2 + 1] << 8 & '\uff00') + (var1[var2] & 255);
   }

   private void intTobytes(int var1, byte[] var2, int var3) {
      var2[var3 + 3] = (byte)(var1 >>> 24);
      var2[var3 + 2] = (byte)(var1 >>> 16);
      var2[var3 + 1] = (byte)(var1 >>> 8);
      var2[var3] = (byte)var1;
   }

   public static byte[] getSBox(String var0) {
      byte[] var1 = (byte[])sBoxes.get(Strings.toUpperCase(var0));
      if (var1 == null) {
         throw new IllegalArgumentException("Unknown S-Box - possible types: \"Default\", \"E-Test\", \"E-A\", \"E-B\", \"E-C\", \"E-D\", \"D-Test\", \"D-A\".");
      } else {
         return Arrays.clone(var1);
      }
   }
}
