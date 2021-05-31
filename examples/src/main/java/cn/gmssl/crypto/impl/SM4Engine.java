package cn.gmssl.crypto.impl;

import cn.gmssl.crypto.util.ByteUtil;
import cn.gmssl.jce.provider.GMConf;
import java.io.FileOutputStream;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.params.KeyParameter;

public class SM4Engine implements BlockCipher {
   private byte[][] sboxTable = new byte[][]{{-42, -112, -23, -2, -52, -31, 61, -73, 22, -74, 20, -62, 40, -5, 44, 5}, {43, 103, -102, 118, 42, -66, 4, -61, -86, 68, 19, 38, 73, -122, 6, -103}, {-100, 66, 80, -12, -111, -17, -104, 122, 51, 84, 11, 67, -19, -49, -84, 98}, {-28, -77, 28, -87, -55, 8, -24, -107, -128, -33, -108, -6, 117, -113, 63, -90}, {71, 7, -89, -4, -13, 115, 23, -70, -125, 89, 60, 25, -26, -123, 79, -88}, {104, 107, -127, -78, 113, 100, -38, -117, -8, -21, 15, 75, 112, 86, -99, 53}, {30, 36, 14, 94, 99, 88, -47, -94, 37, 34, 124, 59, 1, 33, 120, -121}, {-44, 0, 70, 87, -97, -45, 39, 82, 76, 54, 2, -25, -96, -60, -56, -98}, {-22, -65, -118, -46, 64, -57, 56, -75, -93, -9, -14, -50, -7, 97, 21, -95}, {-32, -82, 93, -92, -101, 52, 26, 85, -83, -109, 50, 48, -11, -116, -79, -29}, {29, -10, -30, 46, -126, 102, -54, 96, -64, 41, 35, -85, 13, 83, 78, 111}, {-43, -37, 55, 69, -34, -3, -114, 47, 3, -1, 106, 114, 109, 108, 91, 81}, {-115, 27, -81, -110, -69, -35, -68, 127, 17, -39, 92, 65, 31, 16, 90, -40}, {10, -63, 49, -120, -91, -51, 123, -67, 45, 116, -48, 18, -72, -27, -76, -80}, {-119, 105, -105, 74, 12, -106, 119, 126, 101, -71, -15, 9, -59, 110, -58, -124}, {24, -16, 125, -20, 58, -36, 77, 32, 121, -18, 95, 62, -41, -53, 57, 72}};
   private int[] CK = new int[]{462357, 472066609, 943670861, 1415275113, 1886879365, -1936483679, -1464879427, -993275175, -521670923, -66909679, 404694573, 876298825, 1347903077, 1819507329, -2003855715, -1532251463, -1060647211, -589042959, -117504499, 337322537, 808926789, 1280531041, 1752135293, -2071227751, -1599623499, -1128019247, -656414995, -184876535, 269950501, 741554753, 1213159005, 1684763257};
   private static int[] FK = new int[]{-1548633402, 1453994832, 1736282519, -1301273892};
   public static int BLOCK_SIZE = 16;
   private int[] rk = new int[32];
   private int[] rrk = null;
   private boolean forEncryption = false;

   public void init(boolean var1, CipherParameters var2) throws IllegalArgumentException {
      this.forEncryption = var1;
      byte[] var3 = ((KeyParameter)var2).getKey();
      if (var3.length != BLOCK_SIZE) {
         throw new IllegalArgumentException("unsupported key size");
      } else {
         int[] var4 = new int[4];

         for(int var5 = 0; var5 < 4; ++var5) {
            var4[var5] = ByteUtil.bigEndianToInt(var3, var5 * 4);
         }

         this.keyExpension(var4);
      }
   }

   public String getAlgorithmName() {
      return "SM4";
   }

   public int getBlockSize() {
      return BLOCK_SIZE;
   }

   public int processBlock(byte[] var1, int var2, byte[] var3, int var4) throws DataLengthException, IllegalStateException {
      if (GMConf.sm4Debug) {
         try {
            FileOutputStream var5 = new FileOutputStream("sm4.txt", true);
            var5.write("SM4 processBlock...\r\n".getBytes());
            var5.close();
         } catch (Exception var8) {
            var8.printStackTrace();
         }
      }

      int[] var9 = new int[4];

      for(int var6 = 0; var6 < var9.length; ++var6) {
         var9[var6] = ByteUtil.bigEndianToInt(var1, var6 * 4 + var2);
      }

      int[] var10 = this.R(var9);

      for(int var7 = 0; var7 < 4; ++var7) {
         ByteUtil.intToBigEndian(var10[var7], var3, var4 + var7 * 4);
      }

      return BLOCK_SIZE;
   }

   public void reset() {
      for(int var1 = 0; var1 < 32; ++var1) {
         this.rk[var1] = 0;
      }

      this.rrk = null;
      this.forEncryption = false;
   }

   private byte sbox(int var1) {
      int var2 = var1 >> 4 & 15;
      int var3 = var1 & 15;
      return this.sboxTable[var2][var3];
   }

   private int NL(int var1) {
      int var2 = var1 >> 24 & 255;
      int var3 = var1 >> 16 & 255;
      int var4 = var1 >> 8 & 255;
      int var5 = var1 & 255;
      byte var6 = this.sbox(var2);
      byte var7 = this.sbox(var3);
      byte var8 = this.sbox(var4);
      byte var9 = this.sbox(var5);
      int var10 = ByteUtil.bigEndianToInt((byte)var6, (byte)var7, (byte)var8, (byte)var9);
      return var10;
   }

   private int L(int var1) {
      int var2 = var1 ^ Integer.rotateLeft(var1, 2) ^ Integer.rotateLeft(var1, 10) ^ Integer.rotateLeft(var1, 18) ^ Integer.rotateLeft(var1, 24);
      return var2;
   }

   private int T(int var1) {
      return this.L(this.NL(var1));
   }

   private int L2(int var1) {
      int var2 = var1 ^ Integer.rotateLeft(var1, 13) ^ Integer.rotateLeft(var1, 23);
      return var2;
   }

   private int T2(int var1) {
      return this.L2(this.NL(var1));
   }

   private int[] keyExpension(int[] var1) {
      int[] var2 = new int[36];

      int var3;
      for(var3 = 0; var3 < 4; ++var3) {
         var2[var3] = var1[var3] ^ FK[var3];
      }

      for(var3 = 0; var3 < this.rk.length; ++var3) {
         var2[var3 + 4] = var2[var3] ^ this.T2(var2[var3 + 1] ^ var2[var3 + 2] ^ var2[var3 + 3] ^ this.CK[var3]);
         this.rk[var3] = var2[var3 + 4];
      }

      return var2;
   }

   private int[] R(int[] var1) {
      int[] var2 = this.rk;
      if (!this.forEncryption) {
         if (this.rrk == null) {
            this.rrk = new int[32];

            for(int var3 = 0; var3 < var2.length; ++var3) {
               this.rrk[var3] = var2[var2.length - 1 - var3];
            }
         }

         var2 = this.rrk;
      }

      int[] var5 = new int[36];
      var5[0] = var1[0];
      var5[1] = var1[1];
      var5[2] = var1[2];
      var5[3] = var1[3];

      for(int var4 = 0; var4 < var2.length; ++var4) {
         var5[var4 + 4] = this.F(var5[var4], var5[var4 + 1], var5[var4 + 2], var5[var4 + 3], var2[var4]);
      }

      int[] var6 = new int[]{var5[35], var5[34], var5[33], var5[32]};
      return var6;
   }

   private int F(int var1, int var2, int var3, int var4, int var5) {
      return var1 ^ this.T(var2 ^ var3 ^ var4 ^ var5);
   }
}
