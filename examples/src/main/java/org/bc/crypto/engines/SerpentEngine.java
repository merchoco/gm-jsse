package org.bc.crypto.engines;

import org.bc.crypto.BlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.params.KeyParameter;

public class SerpentEngine implements BlockCipher {
   private static final int BLOCK_SIZE = 16;
   static final int ROUNDS = 32;
   static final int PHI = -1640531527;
   private boolean encrypting;
   private int[] wKey;
   private int X0;
   private int X1;
   private int X2;
   private int X3;

   public void init(boolean var1, CipherParameters var2) {
      if (var2 instanceof KeyParameter) {
         this.encrypting = var1;
         this.wKey = this.makeWorkingKey(((KeyParameter)var2).getKey());
      } else {
         throw new IllegalArgumentException("invalid parameter passed to Serpent init - " + var2.getClass().getName());
      }
   }

   public String getAlgorithmName() {
      return "Serpent";
   }

   public int getBlockSize() {
      return 16;
   }

   public final int processBlock(byte[] var1, int var2, byte[] var3, int var4) {
      if (this.wKey == null) {
         throw new IllegalStateException("Serpent not initialised");
      } else if (var2 + 16 > var1.length) {
         throw new DataLengthException("input buffer too short");
      } else if (var4 + 16 > var3.length) {
         throw new DataLengthException("output buffer too short");
      } else {
         if (this.encrypting) {
            this.encryptBlock(var1, var2, var3, var4);
         } else {
            this.decryptBlock(var1, var2, var3, var4);
         }

         return 16;
      }
   }

   public void reset() {
   }

   private int[] makeWorkingKey(byte[] var1) throws IllegalArgumentException {
      int[] var2 = new int[16];
      boolean var3 = false;
      int var4 = 0;

      int var8;
      for(var8 = var1.length - 4; var8 > 0; var8 -= 4) {
         var2[var4++] = this.bytesToWord(var1, var8);
      }

      if (var8 != 0) {
         throw new IllegalArgumentException("key must be a multiple of 4 bytes");
      } else {
         var2[var4++] = this.bytesToWord(var1, 0);
         if (var4 < 8) {
            var2[var4] = 1;
         }

         short var5 = 132;
         int[] var6 = new int[var5];

         int var7;
         for(var7 = 8; var7 < 16; ++var7) {
            var2[var7] = this.rotateLeft(var2[var7 - 8] ^ var2[var7 - 5] ^ var2[var7 - 3] ^ var2[var7 - 1] ^ -1640531527 ^ var7 - 8, 11);
         }

         System.arraycopy(var2, 8, var6, 0, 8);

         for(var7 = 8; var7 < var5; ++var7) {
            var6[var7] = this.rotateLeft(var6[var7 - 8] ^ var6[var7 - 5] ^ var6[var7 - 3] ^ var6[var7 - 1] ^ -1640531527 ^ var7, 11);
         }

         this.sb3(var6[0], var6[1], var6[2], var6[3]);
         var6[0] = this.X0;
         var6[1] = this.X1;
         var6[2] = this.X2;
         var6[3] = this.X3;
         this.sb2(var6[4], var6[5], var6[6], var6[7]);
         var6[4] = this.X0;
         var6[5] = this.X1;
         var6[6] = this.X2;
         var6[7] = this.X3;
         this.sb1(var6[8], var6[9], var6[10], var6[11]);
         var6[8] = this.X0;
         var6[9] = this.X1;
         var6[10] = this.X2;
         var6[11] = this.X3;
         this.sb0(var6[12], var6[13], var6[14], var6[15]);
         var6[12] = this.X0;
         var6[13] = this.X1;
         var6[14] = this.X2;
         var6[15] = this.X3;
         this.sb7(var6[16], var6[17], var6[18], var6[19]);
         var6[16] = this.X0;
         var6[17] = this.X1;
         var6[18] = this.X2;
         var6[19] = this.X3;
         this.sb6(var6[20], var6[21], var6[22], var6[23]);
         var6[20] = this.X0;
         var6[21] = this.X1;
         var6[22] = this.X2;
         var6[23] = this.X3;
         this.sb5(var6[24], var6[25], var6[26], var6[27]);
         var6[24] = this.X0;
         var6[25] = this.X1;
         var6[26] = this.X2;
         var6[27] = this.X3;
         this.sb4(var6[28], var6[29], var6[30], var6[31]);
         var6[28] = this.X0;
         var6[29] = this.X1;
         var6[30] = this.X2;
         var6[31] = this.X3;
         this.sb3(var6[32], var6[33], var6[34], var6[35]);
         var6[32] = this.X0;
         var6[33] = this.X1;
         var6[34] = this.X2;
         var6[35] = this.X3;
         this.sb2(var6[36], var6[37], var6[38], var6[39]);
         var6[36] = this.X0;
         var6[37] = this.X1;
         var6[38] = this.X2;
         var6[39] = this.X3;
         this.sb1(var6[40], var6[41], var6[42], var6[43]);
         var6[40] = this.X0;
         var6[41] = this.X1;
         var6[42] = this.X2;
         var6[43] = this.X3;
         this.sb0(var6[44], var6[45], var6[46], var6[47]);
         var6[44] = this.X0;
         var6[45] = this.X1;
         var6[46] = this.X2;
         var6[47] = this.X3;
         this.sb7(var6[48], var6[49], var6[50], var6[51]);
         var6[48] = this.X0;
         var6[49] = this.X1;
         var6[50] = this.X2;
         var6[51] = this.X3;
         this.sb6(var6[52], var6[53], var6[54], var6[55]);
         var6[52] = this.X0;
         var6[53] = this.X1;
         var6[54] = this.X2;
         var6[55] = this.X3;
         this.sb5(var6[56], var6[57], var6[58], var6[59]);
         var6[56] = this.X0;
         var6[57] = this.X1;
         var6[58] = this.X2;
         var6[59] = this.X3;
         this.sb4(var6[60], var6[61], var6[62], var6[63]);
         var6[60] = this.X0;
         var6[61] = this.X1;
         var6[62] = this.X2;
         var6[63] = this.X3;
         this.sb3(var6[64], var6[65], var6[66], var6[67]);
         var6[64] = this.X0;
         var6[65] = this.X1;
         var6[66] = this.X2;
         var6[67] = this.X3;
         this.sb2(var6[68], var6[69], var6[70], var6[71]);
         var6[68] = this.X0;
         var6[69] = this.X1;
         var6[70] = this.X2;
         var6[71] = this.X3;
         this.sb1(var6[72], var6[73], var6[74], var6[75]);
         var6[72] = this.X0;
         var6[73] = this.X1;
         var6[74] = this.X2;
         var6[75] = this.X3;
         this.sb0(var6[76], var6[77], var6[78], var6[79]);
         var6[76] = this.X0;
         var6[77] = this.X1;
         var6[78] = this.X2;
         var6[79] = this.X3;
         this.sb7(var6[80], var6[81], var6[82], var6[83]);
         var6[80] = this.X0;
         var6[81] = this.X1;
         var6[82] = this.X2;
         var6[83] = this.X3;
         this.sb6(var6[84], var6[85], var6[86], var6[87]);
         var6[84] = this.X0;
         var6[85] = this.X1;
         var6[86] = this.X2;
         var6[87] = this.X3;
         this.sb5(var6[88], var6[89], var6[90], var6[91]);
         var6[88] = this.X0;
         var6[89] = this.X1;
         var6[90] = this.X2;
         var6[91] = this.X3;
         this.sb4(var6[92], var6[93], var6[94], var6[95]);
         var6[92] = this.X0;
         var6[93] = this.X1;
         var6[94] = this.X2;
         var6[95] = this.X3;
         this.sb3(var6[96], var6[97], var6[98], var6[99]);
         var6[96] = this.X0;
         var6[97] = this.X1;
         var6[98] = this.X2;
         var6[99] = this.X3;
         this.sb2(var6[100], var6[101], var6[102], var6[103]);
         var6[100] = this.X0;
         var6[101] = this.X1;
         var6[102] = this.X2;
         var6[103] = this.X3;
         this.sb1(var6[104], var6[105], var6[106], var6[107]);
         var6[104] = this.X0;
         var6[105] = this.X1;
         var6[106] = this.X2;
         var6[107] = this.X3;
         this.sb0(var6[108], var6[109], var6[110], var6[111]);
         var6[108] = this.X0;
         var6[109] = this.X1;
         var6[110] = this.X2;
         var6[111] = this.X3;
         this.sb7(var6[112], var6[113], var6[114], var6[115]);
         var6[112] = this.X0;
         var6[113] = this.X1;
         var6[114] = this.X2;
         var6[115] = this.X3;
         this.sb6(var6[116], var6[117], var6[118], var6[119]);
         var6[116] = this.X0;
         var6[117] = this.X1;
         var6[118] = this.X2;
         var6[119] = this.X3;
         this.sb5(var6[120], var6[121], var6[122], var6[123]);
         var6[120] = this.X0;
         var6[121] = this.X1;
         var6[122] = this.X2;
         var6[123] = this.X3;
         this.sb4(var6[124], var6[125], var6[126], var6[127]);
         var6[124] = this.X0;
         var6[125] = this.X1;
         var6[126] = this.X2;
         var6[127] = this.X3;
         this.sb3(var6[128], var6[129], var6[130], var6[131]);
         var6[128] = this.X0;
         var6[129] = this.X1;
         var6[130] = this.X2;
         var6[131] = this.X3;
         return var6;
      }
   }

   private int rotateLeft(int var1, int var2) {
      return var1 << var2 | var1 >>> -var2;
   }

   private int rotateRight(int var1, int var2) {
      return var1 >>> var2 | var1 << -var2;
   }

   private int bytesToWord(byte[] var1, int var2) {
      return (var1[var2] & 255) << 24 | (var1[var2 + 1] & 255) << 16 | (var1[var2 + 2] & 255) << 8 | var1[var2 + 3] & 255;
   }

   private void wordToBytes(int var1, byte[] var2, int var3) {
      var2[var3 + 3] = (byte)var1;
      var2[var3 + 2] = (byte)(var1 >>> 8);
      var2[var3 + 1] = (byte)(var1 >>> 16);
      var2[var3] = (byte)(var1 >>> 24);
   }

   private void encryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      this.X3 = this.bytesToWord(var1, var2);
      this.X2 = this.bytesToWord(var1, var2 + 4);
      this.X1 = this.bytesToWord(var1, var2 + 8);
      this.X0 = this.bytesToWord(var1, var2 + 12);
      this.sb0(this.wKey[0] ^ this.X0, this.wKey[1] ^ this.X1, this.wKey[2] ^ this.X2, this.wKey[3] ^ this.X3);
      this.LT();
      this.sb1(this.wKey[4] ^ this.X0, this.wKey[5] ^ this.X1, this.wKey[6] ^ this.X2, this.wKey[7] ^ this.X3);
      this.LT();
      this.sb2(this.wKey[8] ^ this.X0, this.wKey[9] ^ this.X1, this.wKey[10] ^ this.X2, this.wKey[11] ^ this.X3);
      this.LT();
      this.sb3(this.wKey[12] ^ this.X0, this.wKey[13] ^ this.X1, this.wKey[14] ^ this.X2, this.wKey[15] ^ this.X3);
      this.LT();
      this.sb4(this.wKey[16] ^ this.X0, this.wKey[17] ^ this.X1, this.wKey[18] ^ this.X2, this.wKey[19] ^ this.X3);
      this.LT();
      this.sb5(this.wKey[20] ^ this.X0, this.wKey[21] ^ this.X1, this.wKey[22] ^ this.X2, this.wKey[23] ^ this.X3);
      this.LT();
      this.sb6(this.wKey[24] ^ this.X0, this.wKey[25] ^ this.X1, this.wKey[26] ^ this.X2, this.wKey[27] ^ this.X3);
      this.LT();
      this.sb7(this.wKey[28] ^ this.X0, this.wKey[29] ^ this.X1, this.wKey[30] ^ this.X2, this.wKey[31] ^ this.X3);
      this.LT();
      this.sb0(this.wKey[32] ^ this.X0, this.wKey[33] ^ this.X1, this.wKey[34] ^ this.X2, this.wKey[35] ^ this.X3);
      this.LT();
      this.sb1(this.wKey[36] ^ this.X0, this.wKey[37] ^ this.X1, this.wKey[38] ^ this.X2, this.wKey[39] ^ this.X3);
      this.LT();
      this.sb2(this.wKey[40] ^ this.X0, this.wKey[41] ^ this.X1, this.wKey[42] ^ this.X2, this.wKey[43] ^ this.X3);
      this.LT();
      this.sb3(this.wKey[44] ^ this.X0, this.wKey[45] ^ this.X1, this.wKey[46] ^ this.X2, this.wKey[47] ^ this.X3);
      this.LT();
      this.sb4(this.wKey[48] ^ this.X0, this.wKey[49] ^ this.X1, this.wKey[50] ^ this.X2, this.wKey[51] ^ this.X3);
      this.LT();
      this.sb5(this.wKey[52] ^ this.X0, this.wKey[53] ^ this.X1, this.wKey[54] ^ this.X2, this.wKey[55] ^ this.X3);
      this.LT();
      this.sb6(this.wKey[56] ^ this.X0, this.wKey[57] ^ this.X1, this.wKey[58] ^ this.X2, this.wKey[59] ^ this.X3);
      this.LT();
      this.sb7(this.wKey[60] ^ this.X0, this.wKey[61] ^ this.X1, this.wKey[62] ^ this.X2, this.wKey[63] ^ this.X3);
      this.LT();
      this.sb0(this.wKey[64] ^ this.X0, this.wKey[65] ^ this.X1, this.wKey[66] ^ this.X2, this.wKey[67] ^ this.X3);
      this.LT();
      this.sb1(this.wKey[68] ^ this.X0, this.wKey[69] ^ this.X1, this.wKey[70] ^ this.X2, this.wKey[71] ^ this.X3);
      this.LT();
      this.sb2(this.wKey[72] ^ this.X0, this.wKey[73] ^ this.X1, this.wKey[74] ^ this.X2, this.wKey[75] ^ this.X3);
      this.LT();
      this.sb3(this.wKey[76] ^ this.X0, this.wKey[77] ^ this.X1, this.wKey[78] ^ this.X2, this.wKey[79] ^ this.X3);
      this.LT();
      this.sb4(this.wKey[80] ^ this.X0, this.wKey[81] ^ this.X1, this.wKey[82] ^ this.X2, this.wKey[83] ^ this.X3);
      this.LT();
      this.sb5(this.wKey[84] ^ this.X0, this.wKey[85] ^ this.X1, this.wKey[86] ^ this.X2, this.wKey[87] ^ this.X3);
      this.LT();
      this.sb6(this.wKey[88] ^ this.X0, this.wKey[89] ^ this.X1, this.wKey[90] ^ this.X2, this.wKey[91] ^ this.X3);
      this.LT();
      this.sb7(this.wKey[92] ^ this.X0, this.wKey[93] ^ this.X1, this.wKey[94] ^ this.X2, this.wKey[95] ^ this.X3);
      this.LT();
      this.sb0(this.wKey[96] ^ this.X0, this.wKey[97] ^ this.X1, this.wKey[98] ^ this.X2, this.wKey[99] ^ this.X3);
      this.LT();
      this.sb1(this.wKey[100] ^ this.X0, this.wKey[101] ^ this.X1, this.wKey[102] ^ this.X2, this.wKey[103] ^ this.X3);
      this.LT();
      this.sb2(this.wKey[104] ^ this.X0, this.wKey[105] ^ this.X1, this.wKey[106] ^ this.X2, this.wKey[107] ^ this.X3);
      this.LT();
      this.sb3(this.wKey[108] ^ this.X0, this.wKey[109] ^ this.X1, this.wKey[110] ^ this.X2, this.wKey[111] ^ this.X3);
      this.LT();
      this.sb4(this.wKey[112] ^ this.X0, this.wKey[113] ^ this.X1, this.wKey[114] ^ this.X2, this.wKey[115] ^ this.X3);
      this.LT();
      this.sb5(this.wKey[116] ^ this.X0, this.wKey[117] ^ this.X1, this.wKey[118] ^ this.X2, this.wKey[119] ^ this.X3);
      this.LT();
      this.sb6(this.wKey[120] ^ this.X0, this.wKey[121] ^ this.X1, this.wKey[122] ^ this.X2, this.wKey[123] ^ this.X3);
      this.LT();
      this.sb7(this.wKey[124] ^ this.X0, this.wKey[125] ^ this.X1, this.wKey[126] ^ this.X2, this.wKey[127] ^ this.X3);
      this.wordToBytes(this.wKey[131] ^ this.X3, var3, var4);
      this.wordToBytes(this.wKey[130] ^ this.X2, var3, var4 + 4);
      this.wordToBytes(this.wKey[129] ^ this.X1, var3, var4 + 8);
      this.wordToBytes(this.wKey[128] ^ this.X0, var3, var4 + 12);
   }

   private void decryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      this.X3 = this.wKey[131] ^ this.bytesToWord(var1, var2);
      this.X2 = this.wKey[130] ^ this.bytesToWord(var1, var2 + 4);
      this.X1 = this.wKey[129] ^ this.bytesToWord(var1, var2 + 8);
      this.X0 = this.wKey[128] ^ this.bytesToWord(var1, var2 + 12);
      this.ib7(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[124];
      this.X1 ^= this.wKey[125];
      this.X2 ^= this.wKey[126];
      this.X3 ^= this.wKey[127];
      this.inverseLT();
      this.ib6(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[120];
      this.X1 ^= this.wKey[121];
      this.X2 ^= this.wKey[122];
      this.X3 ^= this.wKey[123];
      this.inverseLT();
      this.ib5(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[116];
      this.X1 ^= this.wKey[117];
      this.X2 ^= this.wKey[118];
      this.X3 ^= this.wKey[119];
      this.inverseLT();
      this.ib4(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[112];
      this.X1 ^= this.wKey[113];
      this.X2 ^= this.wKey[114];
      this.X3 ^= this.wKey[115];
      this.inverseLT();
      this.ib3(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[108];
      this.X1 ^= this.wKey[109];
      this.X2 ^= this.wKey[110];
      this.X3 ^= this.wKey[111];
      this.inverseLT();
      this.ib2(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[104];
      this.X1 ^= this.wKey[105];
      this.X2 ^= this.wKey[106];
      this.X3 ^= this.wKey[107];
      this.inverseLT();
      this.ib1(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[100];
      this.X1 ^= this.wKey[101];
      this.X2 ^= this.wKey[102];
      this.X3 ^= this.wKey[103];
      this.inverseLT();
      this.ib0(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[96];
      this.X1 ^= this.wKey[97];
      this.X2 ^= this.wKey[98];
      this.X3 ^= this.wKey[99];
      this.inverseLT();
      this.ib7(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[92];
      this.X1 ^= this.wKey[93];
      this.X2 ^= this.wKey[94];
      this.X3 ^= this.wKey[95];
      this.inverseLT();
      this.ib6(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[88];
      this.X1 ^= this.wKey[89];
      this.X2 ^= this.wKey[90];
      this.X3 ^= this.wKey[91];
      this.inverseLT();
      this.ib5(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[84];
      this.X1 ^= this.wKey[85];
      this.X2 ^= this.wKey[86];
      this.X3 ^= this.wKey[87];
      this.inverseLT();
      this.ib4(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[80];
      this.X1 ^= this.wKey[81];
      this.X2 ^= this.wKey[82];
      this.X3 ^= this.wKey[83];
      this.inverseLT();
      this.ib3(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[76];
      this.X1 ^= this.wKey[77];
      this.X2 ^= this.wKey[78];
      this.X3 ^= this.wKey[79];
      this.inverseLT();
      this.ib2(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[72];
      this.X1 ^= this.wKey[73];
      this.X2 ^= this.wKey[74];
      this.X3 ^= this.wKey[75];
      this.inverseLT();
      this.ib1(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[68];
      this.X1 ^= this.wKey[69];
      this.X2 ^= this.wKey[70];
      this.X3 ^= this.wKey[71];
      this.inverseLT();
      this.ib0(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[64];
      this.X1 ^= this.wKey[65];
      this.X2 ^= this.wKey[66];
      this.X3 ^= this.wKey[67];
      this.inverseLT();
      this.ib7(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[60];
      this.X1 ^= this.wKey[61];
      this.X2 ^= this.wKey[62];
      this.X3 ^= this.wKey[63];
      this.inverseLT();
      this.ib6(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[56];
      this.X1 ^= this.wKey[57];
      this.X2 ^= this.wKey[58];
      this.X3 ^= this.wKey[59];
      this.inverseLT();
      this.ib5(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[52];
      this.X1 ^= this.wKey[53];
      this.X2 ^= this.wKey[54];
      this.X3 ^= this.wKey[55];
      this.inverseLT();
      this.ib4(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[48];
      this.X1 ^= this.wKey[49];
      this.X2 ^= this.wKey[50];
      this.X3 ^= this.wKey[51];
      this.inverseLT();
      this.ib3(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[44];
      this.X1 ^= this.wKey[45];
      this.X2 ^= this.wKey[46];
      this.X3 ^= this.wKey[47];
      this.inverseLT();
      this.ib2(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[40];
      this.X1 ^= this.wKey[41];
      this.X2 ^= this.wKey[42];
      this.X3 ^= this.wKey[43];
      this.inverseLT();
      this.ib1(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[36];
      this.X1 ^= this.wKey[37];
      this.X2 ^= this.wKey[38];
      this.X3 ^= this.wKey[39];
      this.inverseLT();
      this.ib0(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[32];
      this.X1 ^= this.wKey[33];
      this.X2 ^= this.wKey[34];
      this.X3 ^= this.wKey[35];
      this.inverseLT();
      this.ib7(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[28];
      this.X1 ^= this.wKey[29];
      this.X2 ^= this.wKey[30];
      this.X3 ^= this.wKey[31];
      this.inverseLT();
      this.ib6(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[24];
      this.X1 ^= this.wKey[25];
      this.X2 ^= this.wKey[26];
      this.X3 ^= this.wKey[27];
      this.inverseLT();
      this.ib5(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[20];
      this.X1 ^= this.wKey[21];
      this.X2 ^= this.wKey[22];
      this.X3 ^= this.wKey[23];
      this.inverseLT();
      this.ib4(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[16];
      this.X1 ^= this.wKey[17];
      this.X2 ^= this.wKey[18];
      this.X3 ^= this.wKey[19];
      this.inverseLT();
      this.ib3(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[12];
      this.X1 ^= this.wKey[13];
      this.X2 ^= this.wKey[14];
      this.X3 ^= this.wKey[15];
      this.inverseLT();
      this.ib2(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[8];
      this.X1 ^= this.wKey[9];
      this.X2 ^= this.wKey[10];
      this.X3 ^= this.wKey[11];
      this.inverseLT();
      this.ib1(this.X0, this.X1, this.X2, this.X3);
      this.X0 ^= this.wKey[4];
      this.X1 ^= this.wKey[5];
      this.X2 ^= this.wKey[6];
      this.X3 ^= this.wKey[7];
      this.inverseLT();
      this.ib0(this.X0, this.X1, this.X2, this.X3);
      this.wordToBytes(this.X3 ^ this.wKey[3], var3, var4);
      this.wordToBytes(this.X2 ^ this.wKey[2], var3, var4 + 4);
      this.wordToBytes(this.X1 ^ this.wKey[1], var3, var4 + 8);
      this.wordToBytes(this.X0 ^ this.wKey[0], var3, var4 + 12);
   }

   private void sb0(int var1, int var2, int var3, int var4) {
      int var5 = var1 ^ var4;
      int var6 = var3 ^ var5;
      int var7 = var2 ^ var6;
      this.X3 = var1 & var4 ^ var7;
      int var8 = var1 ^ var2 & var5;
      this.X2 = var7 ^ (var3 | var8);
      int var9 = this.X3 & (var6 ^ var8);
      this.X1 = ~var6 ^ var9;
      this.X0 = var9 ^ ~var8;
   }

   private void ib0(int var1, int var2, int var3, int var4) {
      int var5 = ~var1;
      int var6 = var1 ^ var2;
      int var7 = var4 ^ (var5 | var6);
      int var8 = var3 ^ var7;
      this.X2 = var6 ^ var8;
      int var9 = var5 ^ var4 & var6;
      this.X1 = var7 ^ this.X2 & var9;
      this.X3 = var1 & var7 ^ (var8 | this.X1);
      this.X0 = this.X3 ^ var8 ^ var9;
   }

   private void sb1(int var1, int var2, int var3, int var4) {
      int var5 = var2 ^ ~var1;
      int var6 = var3 ^ (var1 | var5);
      this.X2 = var4 ^ var6;
      int var7 = var2 ^ (var4 | var5);
      int var8 = var5 ^ this.X2;
      this.X3 = var8 ^ var6 & var7;
      int var9 = var6 ^ var7;
      this.X1 = this.X3 ^ var9;
      this.X0 = var6 ^ var8 & var9;
   }

   private void ib1(int var1, int var2, int var3, int var4) {
      int var5 = var2 ^ var4;
      int var6 = var1 ^ var2 & var5;
      int var7 = var5 ^ var6;
      this.X3 = var3 ^ var7;
      int var8 = var2 ^ var5 & var6;
      int var9 = this.X3 | var8;
      this.X1 = var6 ^ var9;
      int var10 = ~this.X1;
      int var11 = this.X3 ^ var8;
      this.X0 = var10 ^ var11;
      this.X2 = var7 ^ (var10 | var11);
   }

   private void sb2(int var1, int var2, int var3, int var4) {
      int var5 = ~var1;
      int var6 = var2 ^ var4;
      int var7 = var3 & var5;
      this.X0 = var6 ^ var7;
      int var8 = var3 ^ var5;
      int var9 = var3 ^ this.X0;
      int var10 = var2 & var9;
      this.X3 = var8 ^ var10;
      this.X2 = var1 ^ (var4 | var10) & (this.X0 | var8);
      this.X1 = var6 ^ this.X3 ^ this.X2 ^ (var4 | var5);
   }

   private void ib2(int var1, int var2, int var3, int var4) {
      int var5 = var2 ^ var4;
      int var6 = ~var5;
      int var7 = var1 ^ var3;
      int var8 = var3 ^ var5;
      int var9 = var2 & var8;
      this.X0 = var7 ^ var9;
      int var10 = var1 | var6;
      int var11 = var4 ^ var10;
      int var12 = var7 | var11;
      this.X3 = var5 ^ var12;
      int var13 = ~var8;
      int var14 = this.X0 | this.X3;
      this.X1 = var13 ^ var14;
      this.X2 = var4 & var13 ^ var7 ^ var14;
   }

   private void sb3(int var1, int var2, int var3, int var4) {
      int var5 = var1 ^ var2;
      int var6 = var1 & var3;
      int var7 = var1 | var4;
      int var8 = var3 ^ var4;
      int var9 = var5 & var7;
      int var10 = var6 | var9;
      this.X2 = var8 ^ var10;
      int var11 = var2 ^ var7;
      int var12 = var10 ^ var11;
      int var13 = var8 & var12;
      this.X0 = var5 ^ var13;
      int var14 = this.X2 & this.X0;
      this.X1 = var12 ^ var14;
      this.X3 = (var2 | var4) ^ var8 ^ var14;
   }

   private void ib3(int var1, int var2, int var3, int var4) {
      int var5 = var1 | var2;
      int var6 = var2 ^ var3;
      int var7 = var2 & var6;
      int var8 = var1 ^ var7;
      int var9 = var3 ^ var8;
      int var10 = var4 | var8;
      this.X0 = var6 ^ var10;
      int var11 = var6 | var10;
      int var12 = var4 ^ var11;
      this.X2 = var9 ^ var12;
      int var13 = var5 ^ var12;
      int var14 = this.X0 & var13;
      this.X3 = var8 ^ var14;
      this.X1 = this.X3 ^ this.X0 ^ var13;
   }

   private void sb4(int var1, int var2, int var3, int var4) {
      int var5 = var1 ^ var4;
      int var6 = var4 & var5;
      int var7 = var3 ^ var6;
      int var8 = var2 | var7;
      this.X3 = var5 ^ var8;
      int var9 = ~var2;
      int var10 = var5 | var9;
      this.X0 = var7 ^ var10;
      int var11 = var1 & this.X0;
      int var12 = var5 ^ var9;
      int var13 = var8 & var12;
      this.X2 = var11 ^ var13;
      this.X1 = var1 ^ var7 ^ var12 & this.X2;
   }

   private void ib4(int var1, int var2, int var3, int var4) {
      int var5 = var3 | var4;
      int var6 = var1 & var5;
      int var7 = var2 ^ var6;
      int var8 = var1 & var7;
      int var9 = var3 ^ var8;
      this.X1 = var4 ^ var9;
      int var10 = ~var1;
      int var11 = var9 & this.X1;
      this.X3 = var7 ^ var11;
      int var12 = this.X1 | var10;
      int var13 = var4 ^ var12;
      this.X0 = this.X3 ^ var13;
      this.X2 = var7 & var13 ^ this.X1 ^ var10;
   }

   private void sb5(int var1, int var2, int var3, int var4) {
      int var5 = ~var1;
      int var6 = var1 ^ var2;
      int var7 = var1 ^ var4;
      int var8 = var3 ^ var5;
      int var9 = var6 | var7;
      this.X0 = var8 ^ var9;
      int var10 = var4 & this.X0;
      int var11 = var6 ^ this.X0;
      this.X1 = var10 ^ var11;
      int var12 = var5 | this.X0;
      int var13 = var6 | var10;
      int var14 = var7 ^ var12;
      this.X2 = var13 ^ var14;
      this.X3 = var2 ^ var10 ^ this.X1 & var14;
   }

   private void ib5(int var1, int var2, int var3, int var4) {
      int var5 = ~var3;
      int var6 = var2 & var5;
      int var7 = var4 ^ var6;
      int var8 = var1 & var7;
      int var9 = var2 ^ var5;
      this.X3 = var8 ^ var9;
      int var10 = var2 | this.X3;
      int var11 = var1 & var10;
      this.X1 = var7 ^ var11;
      int var12 = var1 | var4;
      int var13 = var5 ^ var10;
      this.X0 = var12 ^ var13;
      this.X2 = var2 & var12 ^ (var8 | var1 ^ var3);
   }

   private void sb6(int var1, int var2, int var3, int var4) {
      int var5 = ~var1;
      int var6 = var1 ^ var4;
      int var7 = var2 ^ var6;
      int var8 = var5 | var6;
      int var9 = var3 ^ var8;
      this.X1 = var2 ^ var9;
      int var10 = var6 | this.X1;
      int var11 = var4 ^ var10;
      int var12 = var9 & var11;
      this.X2 = var7 ^ var12;
      int var13 = var9 ^ var11;
      this.X0 = this.X2 ^ var13;
      this.X3 = ~var9 ^ var7 & var13;
   }

   private void ib6(int var1, int var2, int var3, int var4) {
      int var5 = ~var1;
      int var6 = var1 ^ var2;
      int var7 = var3 ^ var6;
      int var8 = var3 | var5;
      int var9 = var4 ^ var8;
      this.X1 = var7 ^ var9;
      int var10 = var7 & var9;
      int var11 = var6 ^ var10;
      int var12 = var2 | var11;
      this.X3 = var9 ^ var12;
      int var13 = var2 | this.X3;
      this.X0 = var11 ^ var13;
      this.X2 = var4 & var5 ^ var7 ^ var13;
   }

   private void sb7(int var1, int var2, int var3, int var4) {
      int var5 = var2 ^ var3;
      int var6 = var3 & var5;
      int var7 = var4 ^ var6;
      int var8 = var1 ^ var7;
      int var9 = var4 | var5;
      int var10 = var8 & var9;
      this.X1 = var2 ^ var10;
      int var11 = var7 | this.X1;
      int var12 = var1 & var8;
      this.X3 = var5 ^ var12;
      int var13 = var8 ^ var11;
      int var14 = this.X3 & var13;
      this.X2 = var7 ^ var14;
      this.X0 = ~var13 ^ this.X3 & this.X2;
   }

   private void ib7(int var1, int var2, int var3, int var4) {
      int var5 = var3 | var1 & var2;
      int var6 = var4 & (var1 | var2);
      this.X3 = var5 ^ var6;
      int var7 = ~var4;
      int var8 = var2 ^ var6;
      int var9 = var8 | this.X3 ^ var7;
      this.X1 = var1 ^ var9;
      this.X0 = var3 ^ var8 ^ (var4 | this.X1);
      this.X2 = var5 ^ this.X1 ^ this.X0 ^ var1 & this.X3;
   }

   private void LT() {
      int var1 = this.rotateLeft(this.X0, 13);
      int var2 = this.rotateLeft(this.X2, 3);
      int var3 = this.X1 ^ var1 ^ var2;
      int var4 = this.X3 ^ var2 ^ var1 << 3;
      this.X1 = this.rotateLeft(var3, 1);
      this.X3 = this.rotateLeft(var4, 7);
      this.X0 = this.rotateLeft(var1 ^ this.X1 ^ this.X3, 5);
      this.X2 = this.rotateLeft(var2 ^ this.X3 ^ this.X1 << 7, 22);
   }

   private void inverseLT() {
      int var1 = this.rotateRight(this.X2, 22) ^ this.X3 ^ this.X1 << 7;
      int var2 = this.rotateRight(this.X0, 5) ^ this.X1 ^ this.X3;
      int var3 = this.rotateRight(this.X3, 7);
      int var4 = this.rotateRight(this.X1, 1);
      this.X3 = var3 ^ var1 ^ var2 << 3;
      this.X1 = var4 ^ var2 ^ var1;
      this.X2 = this.rotateRight(var1, 3);
      this.X0 = this.rotateRight(var2, 13);
   }
}
