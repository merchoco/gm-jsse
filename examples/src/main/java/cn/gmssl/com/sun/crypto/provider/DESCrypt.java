package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

class DESCrypt extends SymmetricCipher implements DESConstants {
   private static final int[] s0p = new int[]{4260096, 65536, 1077936128, 1078001920, 4194304, 1073807616, 1073807360, 1077936128, 1073807616, 4260096, 4259840, 1073742080, 1077936384, 4194304, 0, 1073807360, 65536, 1073741824, 4194560, 65792, 1078001920, 4259840, 1073742080, 4194560, 1073741824, 256, 65792, 1078001664, 256, 1077936384, 1078001664, 0, 0, 1078001920, 4194560, 1073807360, 4260096, 65536, 1073742080, 4194560, 1078001664, 256, 65792, 1077936128, 1073807616, 1073741824, 1077936128, 4259840, 1078001920, 65792, 4259840, 1077936384, 4194304, 1073742080, 1073807360, 0, 65536, 4194304, 1077936384, 4260096, 1073741824, 1078001664, 256, 1073807616};
   private static final int[] s1p = new int[]{134352898, 0, 135168, 134348800, 134217730, 4098, 134221824, 135168, 4096, 134348802, 2, 134221824, 131074, 134352896, 134348800, 2, 131072, 134221826, 134348802, 4096, 135170, 134217728, 0, 131074, 134221826, 135170, 134352896, 134217730, 134217728, 131072, 4098, 134352898, 131074, 134352896, 134221824, 135170, 134352898, 131074, 134217730, 0, 134217728, 4098, 131072, 134348802, 4096, 134217728, 135170, 134221826, 134352896, 4096, 0, 134217730, 2, 134352898, 135168, 134348800, 134348802, 131072, 4098, 134221824, 134221826, 2, 134348800, 135168};
   private static final int[] s2p = new int[]{545259520, 8421408, 32, 545259552, 536903680, 8388608, 545259552, 32800, 8388640, 32768, 8421376, 536870912, 545292320, 536870944, 536870912, 545292288, 0, 536903680, 8421408, 32, 536870944, 545292320, 32768, 545259520, 545292288, 8388640, 536903712, 8421376, 32800, 0, 8388608, 536903712, 8421408, 32, 536870912, 32768, 536870944, 536903680, 8421376, 545259552, 0, 8421408, 32800, 545292288, 536903680, 8388608, 545292320, 536870912, 536903712, 545259520, 8388608, 545292320, 32768, 8388640, 545259552, 32800, 8388640, 0, 545292288, 536870944, 545259520, 536903712, 32, 8421376};
   private static final int[] s3p = new int[]{524801, 33554944, 1, 34079233, 0, 34078720, 33554945, 524289, 34079232, 33554433, 33554432, 513, 33554433, 524801, 524288, 33554432, 34078721, 524800, 512, 1, 524800, 33554945, 34078720, 512, 513, 0, 524289, 34079232, 33554944, 34078721, 34079233, 524288, 34078721, 513, 524288, 33554433, 524800, 33554944, 1, 34078720, 33554945, 0, 512, 524289, 0, 34078721, 34079232, 512, 33554432, 34079233, 524801, 524288, 34079233, 1, 33554944, 524801, 524289, 524800, 34078720, 33554945, 513, 33554432, 33554433, 34079232};
   private static final int[] s4p = new int[]{16777216, 8192, 128, 16785540, 16785412, 16777344, 8324, 16785408, 8192, 4, 16777220, 8320, 16777348, 16785412, 16785536, 0, 8320, 16777216, 8196, 132, 16777344, 8324, 0, 16777220, 4, 16777348, 16785540, 8196, 16785408, 128, 132, 16785536, 16785536, 16777348, 8196, 16785408, 8192, 4, 16777220, 16777344, 16777216, 8320, 16785540, 0, 8324, 16777216, 128, 8196, 16777348, 128, 0, 16785540, 16785412, 16785536, 132, 8192, 8320, 16785412, 16777344, 132, 4, 8324, 16785408, 16777220};
   private static final int[] s5p = new int[]{268435464, 262152, 0, 268698624, 262152, 1024, 268436488, 262144, 1032, 268698632, 263168, 268435456, 268436480, 268435464, 268697600, 263176, 262144, 268436488, 268697608, 0, 1024, 8, 268698624, 268697608, 268698632, 268697600, 268435456, 1032, 8, 263168, 263176, 268436480, 1032, 268435456, 268436480, 263176, 268698624, 262152, 0, 268436480, 268435456, 1024, 268697608, 262144, 262152, 268698632, 263168, 8, 268698632, 263168, 262144, 268436488, 268435464, 268697600, 263176, 0, 1024, 268435464, 268436488, 268698624, 268697600, 1032, 8, 268697608};
   private static final int[] s6p = new int[]{2048, 64, 2097216, -2145386496, -2145384384, -2147481600, 2112, 0, 2097152, -2145386432, -2147483584, 2099200, Integer.MIN_VALUE, 2099264, 2099200, -2147483584, -2145386432, 2048, -2147481600, -2145384384, 0, 2097216, -2145386496, 2112, -2145384448, -2147481536, 2099264, Integer.MIN_VALUE, -2147481536, -2145384448, 64, 2097152, -2147481536, 2099200, -2145384448, -2147483584, 2048, 64, 2097152, -2145384448, -2145386432, -2147481536, 2112, 0, 64, -2145386496, Integer.MIN_VALUE, 2097216, 0, -2145386432, 2097216, 2112, -2147483584, 2048, -2145384384, 2097152, 2099264, Integer.MIN_VALUE, -2147481600, -2145384384, -2145386496, 2099264, 2099200, -2147481600};
   private static final int[] s7p = new int[]{68157456, 68173824, 16400, 0, 67125248, 1048592, 68157440, 68173840, 16, 67108864, 1064960, 16400, 1064976, 67125264, 67108880, 68157440, 16384, 1064976, 1048592, 67125248, 68173840, 67108880, 0, 1064960, 67108864, 1048576, 67125264, 68157456, 1048576, 16384, 68173824, 16, 1048576, 16384, 67108880, 68173840, 16400, 67108864, 0, 1064960, 68157456, 67125264, 67125248, 1048592, 68173824, 16, 1048592, 67125248, 68173840, 1048576, 68157440, 67108880, 1064960, 16400, 67125264, 68157440, 16, 68173824, 1064976, 0, 67108864, 68157456, 16384, 1064976};
   private static final int[] permRight0 = new int[]{0, 1073741824, 4194304, 1077936128, 16384, 1073758208, 4210688, 1077952512, 64, 1073741888, 4194368, 1077936192, 16448, 1073758272, 4210752, 1077952576};
   private static final int[] permLeft1 = new int[]{0, 1073741824, 4194304, 1077936128, 16384, 1073758208, 4210688, 1077952512, 64, 1073741888, 4194368, 1077936192, 16448, 1073758272, 4210752, 1077952576};
   private static final int[] permRight2 = new int[]{0, 268435456, 1048576, 269484032, 4096, 268439552, 1052672, 269488128, 16, 268435472, 1048592, 269484048, 4112, 268439568, 1052688, 269488144};
   private static final int[] permLeft3 = new int[]{0, 268435456, 1048576, 269484032, 4096, 268439552, 1052672, 269488128, 16, 268435472, 1048592, 269484048, 4112, 268439568, 1052688, 269488144};
   private static final int[] permRight4 = new int[]{0, 67108864, 262144, 67371008, 1024, 67109888, 263168, 67372032, 4, 67108868, 262148, 67371012, 1028, 67109892, 263172, 67372036};
   private static final int[] permLeft5 = new int[]{0, 67108864, 262144, 67371008, 1024, 67109888, 263168, 67372032, 4, 67108868, 262148, 67371012, 1028, 67109892, 263172, 67372036};
   private static final int[] permRight6 = new int[]{0, 16777216, 65536, 16842752, 256, 16777472, 65792, 16843008, 1, 16777217, 65537, 16842753, 257, 16777473, 65793, 16843009};
   private static final int[] permLeft7 = new int[]{0, 16777216, 65536, 16842752, 256, 16777472, 65792, 16843008, 1, 16777217, 65537, 16842753, 257, 16777473, 65793, 16843009};
   private static final int[] permRight8 = new int[]{0, Integer.MIN_VALUE, 8388608, -2139095040, 32768, -2147450880, 8421376, -2139062272, 128, -2147483520, 8388736, -2139094912, 32896, -2147450752, 8421504, -2139062144};
   private static final int[] permLeft9 = new int[]{0, Integer.MIN_VALUE, 8388608, -2139095040, 32768, -2147450880, 8421376, -2139062272, 128, -2147483520, 8388736, -2139094912, 32896, -2147450752, 8421504, -2139062144};
   private static final int[] permRightA = new int[]{0, 536870912, 2097152, 538968064, 8192, 536879104, 2105344, 538976256, 32, 536870944, 2097184, 538968096, 8224, 536879136, 2105376, 538976288};
   private static final int[] permLeftB = new int[]{0, 536870912, 2097152, 538968064, 8192, 536879104, 2105344, 538976256, 32, 536870944, 2097184, 538968096, 8224, 536879136, 2105376, 538976288};
   private static final int[] permRightC = new int[]{0, 134217728, 524288, 134742016, 2048, 134219776, 526336, 134744064, 8, 134217736, 524296, 134742024, 2056, 134219784, 526344, 134744072};
   private static final int[] permLeftD = new int[]{0, 134217728, 524288, 134742016, 2048, 134219776, 526336, 134744064, 8, 134217736, 524296, 134742024, 2056, 134219784, 526344, 134744072};
   private static final int[] permRightE = new int[]{0, 33554432, 131072, 33685504, 512, 33554944, 131584, 33686016, 2, 33554434, 131074, 33685506, 514, 33554946, 131586, 33686018};
   private static final int[] permLeftF = new int[]{0, 33554432, 131072, 33685504, 512, 33554944, 131584, 33686016, 2, 33554434, 131074, 33685506, 514, 33554946, 131586, 33686018};
   private static final int[] initPermLeft0 = new int[]{0, 32768, 0, 32768, 128, 32896, 128, 32896, 0, 32768, 0, 32768, 128, 32896, 128, 32896};
   private static final int[] initPermRight0 = new int[]{0, 0, 32768, 32768, 0, 0, 32768, 32768, 128, 128, 32896, 32896, 128, 128, 32896, 32896};
   private static final int[] initPermLeft1 = new int[]{0, Integer.MIN_VALUE, 0, Integer.MIN_VALUE, 8388608, -2139095040, 8388608, -2139095040, 0, Integer.MIN_VALUE, 0, Integer.MIN_VALUE, 8388608, -2139095040, 8388608, -2139095040};
   private static final int[] initPermRight1 = new int[]{0, 0, Integer.MIN_VALUE, Integer.MIN_VALUE, 0, 0, Integer.MIN_VALUE, Integer.MIN_VALUE, 8388608, 8388608, -2139095040, -2139095040, 8388608, 8388608, -2139095040, -2139095040};
   private static final int[] initPermLeft2 = new int[]{0, 16384, 0, 16384, 64, 16448, 64, 16448, 0, 16384, 0, 16384, 64, 16448, 64, 16448};
   private static final int[] initPermRight2 = new int[]{0, 0, 16384, 16384, 0, 0, 16384, 16384, 64, 64, 16448, 16448, 64, 64, 16448, 16448};
   private static final int[] initPermLeft3 = new int[]{0, 1073741824, 0, 1073741824, 4194304, 1077936128, 4194304, 1077936128, 0, 1073741824, 0, 1073741824, 4194304, 1077936128, 4194304, 1077936128};
   private static final int[] initPermRight3 = new int[]{0, 0, 1073741824, 1073741824, 0, 0, 1073741824, 1073741824, 4194304, 4194304, 1077936128, 1077936128, 4194304, 4194304, 1077936128, 1077936128};
   private static final int[] initPermLeft4 = new int[]{0, 8192, 0, 8192, 32, 8224, 32, 8224, 0, 8192, 0, 8192, 32, 8224, 32, 8224};
   private static final int[] initPermRight4 = new int[]{0, 0, 8192, 8192, 0, 0, 8192, 8192, 32, 32, 8224, 8224, 32, 32, 8224, 8224};
   private static final int[] initPermLeft5 = new int[]{0, 536870912, 0, 536870912, 2097152, 538968064, 2097152, 538968064, 0, 536870912, 0, 536870912, 2097152, 538968064, 2097152, 538968064};
   private static final int[] initPermRight5 = new int[]{0, 0, 536870912, 536870912, 0, 0, 536870912, 536870912, 2097152, 2097152, 538968064, 538968064, 2097152, 2097152, 538968064, 538968064};
   private static final int[] initPermLeft6 = new int[]{0, 4096, 0, 4096, 16, 4112, 16, 4112, 0, 4096, 0, 4096, 16, 4112, 16, 4112};
   private static final int[] initPermRight6 = new int[]{0, 0, 4096, 4096, 0, 0, 4096, 4096, 16, 16, 4112, 4112, 16, 16, 4112, 4112};
   private static final int[] initPermLeft7 = new int[]{0, 268435456, 0, 268435456, 1048576, 269484032, 1048576, 269484032, 0, 268435456, 0, 268435456, 1048576, 269484032, 1048576, 269484032};
   private static final int[] initPermRight7 = new int[]{0, 0, 268435456, 268435456, 0, 0, 268435456, 268435456, 1048576, 1048576, 269484032, 269484032, 1048576, 1048576, 269484032, 269484032};
   private static final int[] initPermLeft8 = new int[]{0, 2048, 0, 2048, 8, 2056, 8, 2056, 0, 2048, 0, 2048, 8, 2056, 8, 2056};
   private static final int[] initPermRight8 = new int[]{0, 0, 2048, 2048, 0, 0, 2048, 2048, 8, 8, 2056, 2056, 8, 8, 2056, 2056};
   private static final int[] initPermLeft9 = new int[]{0, 134217728, 0, 134217728, 524288, 134742016, 524288, 134742016, 0, 134217728, 0, 134217728, 524288, 134742016, 524288, 134742016};
   private static final int[] initPermRight9 = new int[]{0, 0, 134217728, 134217728, 0, 0, 134217728, 134217728, 524288, 524288, 134742016, 134742016, 524288, 524288, 134742016, 134742016};
   private static final int[] initPermLeftA = new int[]{0, 1024, 0, 1024, 4, 1028, 4, 1028, 0, 1024, 0, 1024, 4, 1028, 4, 1028};
   private static final int[] initPermRightA = new int[]{0, 0, 1024, 1024, 0, 0, 1024, 1024, 4, 4, 1028, 1028, 4, 4, 1028, 1028};
   private static final int[] initPermLeftB = new int[]{0, 67108864, 0, 67108864, 262144, 67371008, 262144, 67371008, 0, 67108864, 0, 67108864, 262144, 67371008, 262144, 67371008};
   private static final int[] initPermRightB = new int[]{0, 0, 67108864, 67108864, 0, 0, 67108864, 67108864, 262144, 262144, 67371008, 67371008, 262144, 262144, 67371008, 67371008};
   private static final int[] initPermLeftC = new int[]{0, 512, 0, 512, 2, 514, 2, 514, 0, 512, 0, 512, 2, 514, 2, 514};
   private static final int[] initPermRightC = new int[]{0, 0, 512, 512, 0, 0, 512, 512, 2, 2, 514, 514, 2, 2, 514, 514};
   private static final int[] initPermLeftD = new int[]{0, 33554432, 0, 33554432, 131072, 33685504, 131072, 33685504, 0, 33554432, 0, 33554432, 131072, 33685504, 131072, 33685504};
   private static final int[] initPermRightD = new int[]{0, 0, 33554432, 33554432, 0, 0, 33554432, 33554432, 131072, 131072, 33685504, 33685504, 131072, 131072, 33685504, 33685504};
   private static final int[] initPermLeftE = new int[]{0, 256, 0, 256, 1, 257, 1, 257, 0, 256, 0, 256, 1, 257, 1, 257};
   private static final int[] initPermRightE = new int[]{0, 0, 256, 256, 0, 0, 256, 256, 1, 1, 257, 257, 1, 1, 257, 257};
   private static final int[] initPermLeftF = new int[]{0, 16777216, 0, 16777216, 65536, 16842752, 65536, 16842752, 0, 16777216, 0, 16777216, 65536, 16842752, 65536, 16842752};
   private static final int[] initPermRightF = new int[]{0, 0, 16777216, 16777216, 0, 0, 16777216, 16777216, 65536, 65536, 16842752, 16842752, 65536, 65536, 16842752, 16842752};
   byte[] expandedKey = null;
   boolean decrypting = false;

   int getBlockSize() {
      return 8;
   }

   void init(boolean var1, String var2, byte[] var3) throws InvalidKeyException {
      this.decrypting = var1;
      if (!var2.equalsIgnoreCase("DES")) {
         throw new InvalidKeyException("Wrong algorithm: DES required");
      } else if (var3.length != 8) {
         throw new InvalidKeyException("Wrong key size");
      } else {
         this.expandKey(var3);
      }
   }

   void encryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      this.cipherBlock(var1, var2, var3, var4);
   }

   void decryptBlock(byte[] var1, int var2, byte[] var3, int var4) {
      this.cipherBlock(var1, var2, var3, var4);
   }

   void cipherBlock(byte[] var1, int var2, byte[] var3, int var4) {
      int var10 = initialPermutationLeft(var1, var2);
      int var11 = initialPermutationRight(var1, var2);
      byte[] var5 = this.expandedKey;
      int var8;
      byte var9;
      if (this.decrypting) {
         var9 = 8;
         var8 = 120;
      } else {
         var9 = -8;
         var8 = 0;
      }

      for(int var7 = 0; var7 < 16; ++var7) {
         int var6 = var11 << 1 | var11 >> 31 & 1;
         var10 ^= s0p[var6 & 63 ^ var5[var8 + 0]] ^ s1p[var6 >> 4 & 63 ^ var5[var8 + 1]] ^ s2p[var6 >> 8 & 63 ^ var5[var8 + 2]] ^ s3p[var6 >> 12 & 63 ^ var5[var8 + 3]] ^ s4p[var6 >> 16 & 63 ^ var5[var8 + 4]] ^ s5p[var6 >> 20 & 63 ^ var5[var8 + 5]] ^ s6p[var6 >> 24 & 63 ^ var5[var8 + 6]];
         var6 = (var11 & 1) << 5 | var11 >> 27 & 31;
         var10 ^= s7p[var6 ^ var5[var8 + 7]];
         var6 = var10;
         var10 = var11;
         var11 = var6;
         var8 -= var9;
      }

      perm(var11, var10, var3, var4);
   }

   private static void perm(int var0, int var1, byte[] var2, int var3) {
      int var5 = permRight0[var0 & 15];
      int var6 = var0 >> 4;
      int var4 = permLeft1[var6 & 15];
      var6 >>= 4;
      var5 |= permRight2[var6 & 15];
      var6 >>= 4;
      var4 |= permLeft3[var6 & 15];
      var6 >>= 4;
      var5 |= permRight4[var6 & 15];
      var6 >>= 4;
      var4 |= permLeft5[var6 & 15];
      var6 >>= 4;
      var5 |= permRight6[var6 & 15];
      var6 >>= 4;
      var4 |= permLeft7[var6 & 15];
      var5 |= permRight8[var1 & 15];
      var6 = var1 >> 4;
      var4 |= permLeft9[var6 & 15];
      var6 >>= 4;
      var5 |= permRightA[var6 & 15];
      var6 >>= 4;
      var4 |= permLeftB[var6 & 15];
      var6 >>= 4;
      var5 |= permRightC[var6 & 15];
      var6 >>= 4;
      var4 |= permLeftD[var6 & 15];
      var6 >>= 4;
      var5 |= permRightE[var6 & 15];
      var6 >>= 4;
      var4 |= permLeftF[var6 & 15];
      var2[var3 + 0] = (byte)var4;
      var2[var3 + 1] = (byte)(var4 >> 8);
      var2[var3 + 2] = (byte)(var4 >> 16);
      var2[var3 + 3] = (byte)(var4 >> 24);
      var2[var3 + 4] = (byte)var5;
      var2[var3 + 5] = (byte)(var5 >> 8);
      var2[var3 + 6] = (byte)(var5 >> 16);
      var2[var3 + 7] = (byte)(var5 >> 24);
   }

   private static int initialPermutationLeft(byte[] var0, int var1) {
      int var2 = initPermLeft1[var0[var1] & 15];
      var2 |= initPermLeft0[var0[var1] >> 4 & 15];
      var2 |= initPermLeft3[var0[var1 + 1] & 15];
      var2 |= initPermLeft2[var0[var1 + 1] >> 4 & 15];
      var2 |= initPermLeft5[var0[var1 + 2] & 15];
      var2 |= initPermLeft4[var0[var1 + 2] >> 4 & 15];
      var2 |= initPermLeft7[var0[var1 + 3] & 15];
      var2 |= initPermLeft6[var0[var1 + 3] >> 4 & 15];
      var2 |= initPermLeft9[var0[var1 + 4] & 15];
      var2 |= initPermLeft8[var0[var1 + 4] >> 4 & 15];
      var2 |= initPermLeftB[var0[var1 + 5] & 15];
      var2 |= initPermLeftA[var0[var1 + 5] >> 4 & 15];
      var2 |= initPermLeftD[var0[var1 + 6] & 15];
      var2 |= initPermLeftC[var0[var1 + 6] >> 4 & 15];
      var2 |= initPermLeftF[var0[var1 + 7] & 15];
      var2 |= initPermLeftE[var0[var1 + 7] >> 4 & 15];
      return var2;
   }

   private static int initialPermutationRight(byte[] var0, int var1) {
      int var2 = initPermRight1[var0[var1] & 15];
      var2 |= initPermRight0[var0[var1] >> 4 & 15];
      var2 |= initPermRight3[var0[var1 + 1] & 15];
      var2 |= initPermRight2[var0[var1 + 1] >> 4 & 15];
      var2 |= initPermRight5[var0[var1 + 2] & 15];
      var2 |= initPermRight4[var0[var1 + 2] >> 4 & 15];
      var2 |= initPermRight7[var0[var1 + 3] & 15];
      var2 |= initPermRight6[var0[var1 + 3] >> 4 & 15];
      var2 |= initPermRight9[var0[var1 + 4] & 15];
      var2 |= initPermRight8[var0[var1 + 4] >> 4 & 15];
      var2 |= initPermRightB[var0[var1 + 5] & 15];
      var2 |= initPermRightA[var0[var1 + 5] >> 4 & 15];
      var2 |= initPermRightD[var0[var1 + 6] & 15];
      var2 |= initPermRightC[var0[var1 + 6] >> 4 & 15];
      var2 |= initPermRightF[var0[var1 + 7] & 15];
      var2 |= initPermRightE[var0[var1 + 7] >> 4 & 15];
      return var2;
   }

   void expandKey(byte[] var1) {
      byte[] var3 = new byte[128];
      byte var2 = var1[0];
      if ((var2 & 128) != 0) {
         var3[3] = (byte)(var3[3] | 2);
         var3[9] = (byte)(var3[9] | 8);
         var3[18] = (byte)(var3[18] | 8);
         var3[27] = (byte)(var3[27] | 32);
         var3[33] = (byte)(var3[33] | 2);
         var3[42] = (byte)(var3[42] | 16);
         var3[48] = (byte)(var3[48] | 8);
         var3[65] = (byte)(var3[65] | 16);
         var3[74] = (byte)(var3[74] | 2);
         var3[80] = (byte)(var3[80] | 2);
         var3[89] = (byte)(var3[89] | 4);
         var3[99] = (byte)(var3[99] | 16);
         var3[104] = (byte)(var3[104] | 4);
         var3[122] = (byte)(var3[122] | 32);
      }

      if ((var2 & 64) != 0) {
         var3[1] = (byte)(var3[1] | 4);
         var3[8] = (byte)(var3[8] | 1);
         var3[18] = (byte)(var3[18] | 4);
         var3[25] = (byte)(var3[25] | 32);
         var3[34] = (byte)(var3[34] | 32);
         var3[41] = (byte)(var3[41] | 8);
         var3[50] = (byte)(var3[50] | 8);
         var3[59] = (byte)(var3[59] | 32);
         var3[64] = (byte)(var3[64] | 16);
         var3[75] = (byte)(var3[75] | 4);
         var3[90] = (byte)(var3[90] | 1);
         var3[97] = (byte)(var3[97] | 16);
         var3[106] = (byte)(var3[106] | 2);
         var3[112] = (byte)(var3[112] | 2);
         var3[123] = (byte)(var3[123] | 1);
      }

      if ((var2 & 32) != 0) {
         var3[2] = (byte)(var3[2] | 1);
         var3[19] = (byte)(var3[19] | 8);
         var3[35] = (byte)(var3[35] | 1);
         var3[40] = (byte)(var3[40] | 1);
         var3[50] = (byte)(var3[50] | 4);
         var3[57] = (byte)(var3[57] | 32);
         var3[75] = (byte)(var3[75] | 2);
         var3[80] = (byte)(var3[80] | 32);
         var3[89] = (byte)(var3[89] | 1);
         var3[96] = (byte)(var3[96] | 16);
         var3[107] = (byte)(var3[107] | 4);
         var3[120] = (byte)(var3[120] | 8);
      }

      if ((var2 & 16) != 0) {
         var3[4] = (byte)(var3[4] | 32);
         var3[20] = (byte)(var3[20] | 2);
         var3[31] = (byte)(var3[31] | 4);
         var3[37] = (byte)(var3[37] | 32);
         var3[47] = (byte)(var3[47] | 1);
         var3[54] = (byte)(var3[54] | 1);
         var3[63] = (byte)(var3[63] | 2);
         var3[68] = (byte)(var3[68] | 1);
         var3[78] = (byte)(var3[78] | 4);
         var3[84] = (byte)(var3[84] | 8);
         var3[101] = (byte)(var3[101] | 16);
         var3[108] = (byte)(var3[108] | 4);
         var3[119] = (byte)(var3[119] | 16);
         var3[126] = (byte)(var3[126] | 8);
      }

      if ((var2 & 8) != 0) {
         var3[5] = (byte)(var3[5] | 4);
         var3[15] = (byte)(var3[15] | 4);
         var3[21] = (byte)(var3[21] | 32);
         var3[31] = (byte)(var3[31] | 1);
         var3[38] = (byte)(var3[38] | 1);
         var3[47] = (byte)(var3[47] | 2);
         var3[53] = (byte)(var3[53] | 2);
         var3[68] = (byte)(var3[68] | 8);
         var3[85] = (byte)(var3[85] | 16);
         var3[92] = (byte)(var3[92] | 4);
         var3[103] = (byte)(var3[103] | 16);
         var3[108] = (byte)(var3[108] | 32);
         var3[118] = (byte)(var3[118] | 32);
         var3[124] = (byte)(var3[124] | 2);
      }

      if ((var2 & 4) != 0) {
         var3[15] = (byte)(var3[15] | 2);
         var3[21] = (byte)(var3[21] | 2);
         var3[39] = (byte)(var3[39] | 8);
         var3[46] = (byte)(var3[46] | 16);
         var3[55] = (byte)(var3[55] | 32);
         var3[61] = (byte)(var3[61] | 1);
         var3[71] = (byte)(var3[71] | 16);
         var3[76] = (byte)(var3[76] | 32);
         var3[86] = (byte)(var3[86] | 32);
         var3[93] = (byte)(var3[93] | 4);
         var3[102] = (byte)(var3[102] | 2);
         var3[108] = (byte)(var3[108] | 16);
         var3[117] = (byte)(var3[117] | 8);
         var3[126] = (byte)(var3[126] | 1);
      }

      if ((var2 & 2) != 0) {
         var3[14] = (byte)(var3[14] | 16);
         var3[23] = (byte)(var3[23] | 32);
         var3[29] = (byte)(var3[29] | 1);
         var3[38] = (byte)(var3[38] | 8);
         var3[52] = (byte)(var3[52] | 2);
         var3[63] = (byte)(var3[63] | 4);
         var3[70] = (byte)(var3[70] | 2);
         var3[76] = (byte)(var3[76] | 16);
         var3[85] = (byte)(var3[85] | 8);
         var3[100] = (byte)(var3[100] | 1);
         var3[110] = (byte)(var3[110] | 4);
         var3[116] = (byte)(var3[116] | 8);
         var3[127] = (byte)(var3[127] | 8);
      }

      var2 = var1[1];
      if ((var2 & 128) != 0) {
         var3[1] = (byte)(var3[1] | 8);
         var3[8] = (byte)(var3[8] | 32);
         var3[17] = (byte)(var3[17] | 1);
         var3[24] = (byte)(var3[24] | 16);
         var3[35] = (byte)(var3[35] | 4);
         var3[50] = (byte)(var3[50] | 1);
         var3[57] = (byte)(var3[57] | 16);
         var3[67] = (byte)(var3[67] | 8);
         var3[83] = (byte)(var3[83] | 1);
         var3[88] = (byte)(var3[88] | 1);
         var3[98] = (byte)(var3[98] | 4);
         var3[105] = (byte)(var3[105] | 32);
         var3[114] = (byte)(var3[114] | 32);
         var3[123] = (byte)(var3[123] | 2);
      }

      if ((var2 & 64) != 0) {
         var3[0] = (byte)(var3[0] | 1);
         var3[11] = (byte)(var3[11] | 16);
         var3[16] = (byte)(var3[16] | 4);
         var3[35] = (byte)(var3[35] | 2);
         var3[40] = (byte)(var3[40] | 32);
         var3[49] = (byte)(var3[49] | 1);
         var3[56] = (byte)(var3[56] | 16);
         var3[65] = (byte)(var3[65] | 2);
         var3[74] = (byte)(var3[74] | 16);
         var3[80] = (byte)(var3[80] | 8);
         var3[99] = (byte)(var3[99] | 8);
         var3[115] = (byte)(var3[115] | 1);
         var3[121] = (byte)(var3[121] | 4);
      }

      if ((var2 & 32) != 0) {
         var3[9] = (byte)(var3[9] | 16);
         var3[18] = (byte)(var3[18] | 2);
         var3[24] = (byte)(var3[24] | 2);
         var3[33] = (byte)(var3[33] | 4);
         var3[43] = (byte)(var3[43] | 16);
         var3[48] = (byte)(var3[48] | 4);
         var3[66] = (byte)(var3[66] | 32);
         var3[73] = (byte)(var3[73] | 8);
         var3[82] = (byte)(var3[82] | 8);
         var3[91] = (byte)(var3[91] | 32);
         var3[97] = (byte)(var3[97] | 2);
         var3[106] = (byte)(var3[106] | 16);
         var3[112] = (byte)(var3[112] | 8);
         var3[122] = (byte)(var3[122] | 1);
      }

      if ((var2 & 16) != 0) {
         var3[14] = (byte)(var3[14] | 32);
         var3[21] = (byte)(var3[21] | 4);
         var3[30] = (byte)(var3[30] | 2);
         var3[36] = (byte)(var3[36] | 16);
         var3[45] = (byte)(var3[45] | 8);
         var3[60] = (byte)(var3[60] | 1);
         var3[69] = (byte)(var3[69] | 2);
         var3[87] = (byte)(var3[87] | 8);
         var3[94] = (byte)(var3[94] | 16);
         var3[103] = (byte)(var3[103] | 32);
         var3[109] = (byte)(var3[109] | 1);
         var3[118] = (byte)(var3[118] | 8);
         var3[124] = (byte)(var3[124] | 32);
      }

      if ((var2 & 8) != 0) {
         var3[7] = (byte)(var3[7] | 4);
         var3[14] = (byte)(var3[14] | 2);
         var3[20] = (byte)(var3[20] | 16);
         var3[29] = (byte)(var3[29] | 8);
         var3[44] = (byte)(var3[44] | 1);
         var3[54] = (byte)(var3[54] | 4);
         var3[60] = (byte)(var3[60] | 8);
         var3[71] = (byte)(var3[71] | 8);
         var3[78] = (byte)(var3[78] | 16);
         var3[87] = (byte)(var3[87] | 32);
         var3[93] = (byte)(var3[93] | 1);
         var3[102] = (byte)(var3[102] | 8);
         var3[116] = (byte)(var3[116] | 2);
         var3[125] = (byte)(var3[125] | 4);
      }

      if ((var2 & 4) != 0) {
         var3[7] = (byte)(var3[7] | 2);
         var3[12] = (byte)(var3[12] | 1);
         var3[22] = (byte)(var3[22] | 4);
         var3[28] = (byte)(var3[28] | 8);
         var3[45] = (byte)(var3[45] | 16);
         var3[52] = (byte)(var3[52] | 4);
         var3[63] = (byte)(var3[63] | 16);
         var3[70] = (byte)(var3[70] | 8);
         var3[84] = (byte)(var3[84] | 2);
         var3[95] = (byte)(var3[95] | 4);
         var3[101] = (byte)(var3[101] | 32);
         var3[111] = (byte)(var3[111] | 1);
         var3[118] = (byte)(var3[118] | 1);
      }

      if ((var2 & 2) != 0) {
         var3[6] = (byte)(var3[6] | 16);
         var3[13] = (byte)(var3[13] | 16);
         var3[20] = (byte)(var3[20] | 4);
         var3[31] = (byte)(var3[31] | 16);
         var3[36] = (byte)(var3[36] | 32);
         var3[46] = (byte)(var3[46] | 32);
         var3[53] = (byte)(var3[53] | 4);
         var3[62] = (byte)(var3[62] | 2);
         var3[69] = (byte)(var3[69] | 32);
         var3[79] = (byte)(var3[79] | 1);
         var3[86] = (byte)(var3[86] | 1);
         var3[95] = (byte)(var3[95] | 2);
         var3[101] = (byte)(var3[101] | 2);
         var3[119] = (byte)(var3[119] | 8);
      }

      var2 = var1[2];
      if ((var2 & 128) != 0) {
         var3[0] = (byte)(var3[0] | 32);
         var3[10] = (byte)(var3[10] | 8);
         var3[19] = (byte)(var3[19] | 32);
         var3[25] = (byte)(var3[25] | 2);
         var3[34] = (byte)(var3[34] | 16);
         var3[40] = (byte)(var3[40] | 8);
         var3[59] = (byte)(var3[59] | 8);
         var3[66] = (byte)(var3[66] | 2);
         var3[72] = (byte)(var3[72] | 2);
         var3[81] = (byte)(var3[81] | 4);
         var3[91] = (byte)(var3[91] | 16);
         var3[96] = (byte)(var3[96] | 4);
         var3[115] = (byte)(var3[115] | 2);
         var3[121] = (byte)(var3[121] | 8);
      }

      if ((var2 & 64) != 0) {
         var3[3] = (byte)(var3[3] | 16);
         var3[10] = (byte)(var3[10] | 4);
         var3[17] = (byte)(var3[17] | 32);
         var3[26] = (byte)(var3[26] | 32);
         var3[33] = (byte)(var3[33] | 8);
         var3[42] = (byte)(var3[42] | 8);
         var3[51] = (byte)(var3[51] | 32);
         var3[57] = (byte)(var3[57] | 2);
         var3[67] = (byte)(var3[67] | 4);
         var3[82] = (byte)(var3[82] | 1);
         var3[89] = (byte)(var3[89] | 16);
         var3[98] = (byte)(var3[98] | 2);
         var3[104] = (byte)(var3[104] | 2);
         var3[113] = (byte)(var3[113] | 4);
         var3[120] = (byte)(var3[120] | 1);
      }

      if ((var2 & 32) != 0) {
         var3[1] = (byte)(var3[1] | 16);
         var3[11] = (byte)(var3[11] | 8);
         var3[27] = (byte)(var3[27] | 1);
         var3[32] = (byte)(var3[32] | 1);
         var3[42] = (byte)(var3[42] | 4);
         var3[49] = (byte)(var3[49] | 32);
         var3[58] = (byte)(var3[58] | 32);
         var3[67] = (byte)(var3[67] | 2);
         var3[72] = (byte)(var3[72] | 32);
         var3[81] = (byte)(var3[81] | 1);
         var3[88] = (byte)(var3[88] | 16);
         var3[99] = (byte)(var3[99] | 4);
         var3[114] = (byte)(var3[114] | 1);
      }

      if ((var2 & 16) != 0) {
         var3[6] = (byte)(var3[6] | 32);
         var3[12] = (byte)(var3[12] | 2);
         var3[23] = (byte)(var3[23] | 4);
         var3[29] = (byte)(var3[29] | 32);
         var3[39] = (byte)(var3[39] | 1);
         var3[46] = (byte)(var3[46] | 1);
         var3[55] = (byte)(var3[55] | 2);
         var3[61] = (byte)(var3[61] | 2);
         var3[70] = (byte)(var3[70] | 4);
         var3[76] = (byte)(var3[76] | 8);
         var3[93] = (byte)(var3[93] | 16);
         var3[100] = (byte)(var3[100] | 4);
         var3[111] = (byte)(var3[111] | 16);
         var3[116] = (byte)(var3[116] | 32);
      }

      if ((var2 & 8) != 0) {
         var3[6] = (byte)(var3[6] | 2);
         var3[13] = (byte)(var3[13] | 32);
         var3[23] = (byte)(var3[23] | 1);
         var3[30] = (byte)(var3[30] | 1);
         var3[39] = (byte)(var3[39] | 2);
         var3[45] = (byte)(var3[45] | 2);
         var3[63] = (byte)(var3[63] | 8);
         var3[77] = (byte)(var3[77] | 16);
         var3[84] = (byte)(var3[84] | 4);
         var3[95] = (byte)(var3[95] | 16);
         var3[100] = (byte)(var3[100] | 32);
         var3[110] = (byte)(var3[110] | 32);
         var3[117] = (byte)(var3[117] | 4);
         var3[127] = (byte)(var3[127] | 4);
      }

      if ((var2 & 4) != 0) {
         var3[4] = (byte)(var3[4] | 1);
         var3[13] = (byte)(var3[13] | 2);
         var3[31] = (byte)(var3[31] | 8);
         var3[38] = (byte)(var3[38] | 16);
         var3[47] = (byte)(var3[47] | 32);
         var3[53] = (byte)(var3[53] | 1);
         var3[62] = (byte)(var3[62] | 8);
         var3[68] = (byte)(var3[68] | 32);
         var3[78] = (byte)(var3[78] | 32);
         var3[85] = (byte)(var3[85] | 4);
         var3[94] = (byte)(var3[94] | 2);
         var3[100] = (byte)(var3[100] | 16);
         var3[109] = (byte)(var3[109] | 8);
         var3[127] = (byte)(var3[127] | 2);
      }

      if ((var2 & 2) != 0) {
         var3[5] = (byte)(var3[5] | 16);
         var3[15] = (byte)(var3[15] | 32);
         var3[21] = (byte)(var3[21] | 1);
         var3[30] = (byte)(var3[30] | 8);
         var3[44] = (byte)(var3[44] | 2);
         var3[55] = (byte)(var3[55] | 4);
         var3[61] = (byte)(var3[61] | 32);
         var3[68] = (byte)(var3[68] | 16);
         var3[77] = (byte)(var3[77] | 8);
         var3[92] = (byte)(var3[92] | 1);
         var3[102] = (byte)(var3[102] | 4);
         var3[108] = (byte)(var3[108] | 8);
         var3[126] = (byte)(var3[126] | 16);
      }

      var2 = var1[3];
      if ((var2 & 128) != 0) {
         var3[2] = (byte)(var3[2] | 8);
         var3[9] = (byte)(var3[9] | 1);
         var3[16] = (byte)(var3[16] | 16);
         var3[27] = (byte)(var3[27] | 4);
         var3[42] = (byte)(var3[42] | 1);
         var3[49] = (byte)(var3[49] | 16);
         var3[58] = (byte)(var3[58] | 2);
         var3[75] = (byte)(var3[75] | 1);
         var3[80] = (byte)(var3[80] | 1);
         var3[90] = (byte)(var3[90] | 4);
         var3[97] = (byte)(var3[97] | 32);
         var3[106] = (byte)(var3[106] | 32);
         var3[113] = (byte)(var3[113] | 8);
         var3[120] = (byte)(var3[120] | 32);
      }

      if ((var2 & 64) != 0) {
         var3[2] = (byte)(var3[2] | 4);
         var3[8] = (byte)(var3[8] | 4);
         var3[27] = (byte)(var3[27] | 2);
         var3[32] = (byte)(var3[32] | 32);
         var3[41] = (byte)(var3[41] | 1);
         var3[48] = (byte)(var3[48] | 16);
         var3[59] = (byte)(var3[59] | 4);
         var3[66] = (byte)(var3[66] | 16);
         var3[72] = (byte)(var3[72] | 8);
         var3[91] = (byte)(var3[91] | 8);
         var3[107] = (byte)(var3[107] | 1);
         var3[112] = (byte)(var3[112] | 1);
         var3[123] = (byte)(var3[123] | 16);
      }

      if ((var2 & 32) != 0) {
         var3[3] = (byte)(var3[3] | 8);
         var3[10] = (byte)(var3[10] | 2);
         var3[16] = (byte)(var3[16] | 2);
         var3[25] = (byte)(var3[25] | 4);
         var3[35] = (byte)(var3[35] | 16);
         var3[40] = (byte)(var3[40] | 4);
         var3[59] = (byte)(var3[59] | 2);
         var3[65] = (byte)(var3[65] | 8);
         var3[74] = (byte)(var3[74] | 8);
         var3[83] = (byte)(var3[83] | 32);
         var3[89] = (byte)(var3[89] | 2);
         var3[98] = (byte)(var3[98] | 16);
         var3[104] = (byte)(var3[104] | 8);
         var3[121] = (byte)(var3[121] | 16);
      }

      if ((var2 & 16) != 0) {
         var3[4] = (byte)(var3[4] | 2);
         var3[13] = (byte)(var3[13] | 4);
         var3[22] = (byte)(var3[22] | 2);
         var3[28] = (byte)(var3[28] | 16);
         var3[37] = (byte)(var3[37] | 8);
         var3[52] = (byte)(var3[52] | 1);
         var3[62] = (byte)(var3[62] | 4);
         var3[79] = (byte)(var3[79] | 8);
         var3[86] = (byte)(var3[86] | 16);
         var3[95] = (byte)(var3[95] | 32);
         var3[101] = (byte)(var3[101] | 1);
         var3[110] = (byte)(var3[110] | 8);
         var3[126] = (byte)(var3[126] | 32);
      }

      if ((var2 & 8) != 0) {
         var3[5] = (byte)(var3[5] | 32);
         var3[12] = (byte)(var3[12] | 16);
         var3[21] = (byte)(var3[21] | 8);
         var3[36] = (byte)(var3[36] | 1);
         var3[46] = (byte)(var3[46] | 4);
         var3[52] = (byte)(var3[52] | 8);
         var3[70] = (byte)(var3[70] | 16);
         var3[79] = (byte)(var3[79] | 32);
         var3[85] = (byte)(var3[85] | 1);
         var3[94] = (byte)(var3[94] | 8);
         var3[108] = (byte)(var3[108] | 2);
         var3[119] = (byte)(var3[119] | 4);
         var3[126] = (byte)(var3[126] | 2);
      }

      if ((var2 & 4) != 0) {
         var3[5] = (byte)(var3[5] | 2);
         var3[14] = (byte)(var3[14] | 4);
         var3[20] = (byte)(var3[20] | 8);
         var3[37] = (byte)(var3[37] | 16);
         var3[44] = (byte)(var3[44] | 4);
         var3[55] = (byte)(var3[55] | 16);
         var3[60] = (byte)(var3[60] | 32);
         var3[76] = (byte)(var3[76] | 2);
         var3[87] = (byte)(var3[87] | 4);
         var3[93] = (byte)(var3[93] | 32);
         var3[103] = (byte)(var3[103] | 1);
         var3[110] = (byte)(var3[110] | 1);
         var3[119] = (byte)(var3[119] | 2);
         var3[124] = (byte)(var3[124] | 1);
      }

      if ((var2 & 2) != 0) {
         var3[7] = (byte)(var3[7] | 32);
         var3[12] = (byte)(var3[12] | 4);
         var3[23] = (byte)(var3[23] | 16);
         var3[28] = (byte)(var3[28] | 32);
         var3[38] = (byte)(var3[38] | 32);
         var3[45] = (byte)(var3[45] | 4);
         var3[54] = (byte)(var3[54] | 2);
         var3[60] = (byte)(var3[60] | 16);
         var3[71] = (byte)(var3[71] | 1);
         var3[78] = (byte)(var3[78] | 1);
         var3[87] = (byte)(var3[87] | 2);
         var3[93] = (byte)(var3[93] | 2);
         var3[111] = (byte)(var3[111] | 8);
         var3[118] = (byte)(var3[118] | 16);
         var3[125] = (byte)(var3[125] | 16);
      }

      var2 = var1[4];
      if ((var2 & 128) != 0) {
         var3[1] = (byte)(var3[1] | 1);
         var3[11] = (byte)(var3[11] | 32);
         var3[17] = (byte)(var3[17] | 2);
         var3[26] = (byte)(var3[26] | 16);
         var3[32] = (byte)(var3[32] | 8);
         var3[51] = (byte)(var3[51] | 8);
         var3[64] = (byte)(var3[64] | 2);
         var3[73] = (byte)(var3[73] | 4);
         var3[83] = (byte)(var3[83] | 16);
         var3[88] = (byte)(var3[88] | 4);
         var3[107] = (byte)(var3[107] | 2);
         var3[112] = (byte)(var3[112] | 32);
         var3[122] = (byte)(var3[122] | 8);
      }

      if ((var2 & 64) != 0) {
         var3[0] = (byte)(var3[0] | 4);
         var3[9] = (byte)(var3[9] | 32);
         var3[18] = (byte)(var3[18] | 32);
         var3[25] = (byte)(var3[25] | 8);
         var3[34] = (byte)(var3[34] | 8);
         var3[43] = (byte)(var3[43] | 32);
         var3[49] = (byte)(var3[49] | 2);
         var3[58] = (byte)(var3[58] | 16);
         var3[74] = (byte)(var3[74] | 1);
         var3[81] = (byte)(var3[81] | 16);
         var3[90] = (byte)(var3[90] | 2);
         var3[96] = (byte)(var3[96] | 2);
         var3[105] = (byte)(var3[105] | 4);
         var3[115] = (byte)(var3[115] | 16);
         var3[122] = (byte)(var3[122] | 4);
      }

      if ((var2 & 32) != 0) {
         var3[2] = (byte)(var3[2] | 2);
         var3[19] = (byte)(var3[19] | 1);
         var3[24] = (byte)(var3[24] | 1);
         var3[34] = (byte)(var3[34] | 4);
         var3[41] = (byte)(var3[41] | 32);
         var3[50] = (byte)(var3[50] | 32);
         var3[57] = (byte)(var3[57] | 8);
         var3[64] = (byte)(var3[64] | 32);
         var3[73] = (byte)(var3[73] | 1);
         var3[80] = (byte)(var3[80] | 16);
         var3[91] = (byte)(var3[91] | 4);
         var3[106] = (byte)(var3[106] | 1);
         var3[113] = (byte)(var3[113] | 16);
         var3[123] = (byte)(var3[123] | 8);
      }

      if ((var2 & 16) != 0) {
         var3[3] = (byte)(var3[3] | 4);
         var3[10] = (byte)(var3[10] | 16);
         var3[16] = (byte)(var3[16] | 8);
         var3[35] = (byte)(var3[35] | 8);
         var3[51] = (byte)(var3[51] | 1);
         var3[56] = (byte)(var3[56] | 1);
         var3[67] = (byte)(var3[67] | 16);
         var3[72] = (byte)(var3[72] | 4);
         var3[91] = (byte)(var3[91] | 2);
         var3[96] = (byte)(var3[96] | 32);
         var3[105] = (byte)(var3[105] | 1);
         var3[112] = (byte)(var3[112] | 16);
         var3[121] = (byte)(var3[121] | 2);
      }

      if ((var2 & 8) != 0) {
         var3[4] = (byte)(var3[4] | 16);
         var3[15] = (byte)(var3[15] | 1);
         var3[22] = (byte)(var3[22] | 1);
         var3[31] = (byte)(var3[31] | 2);
         var3[37] = (byte)(var3[37] | 2);
         var3[55] = (byte)(var3[55] | 8);
         var3[62] = (byte)(var3[62] | 16);
         var3[69] = (byte)(var3[69] | 16);
         var3[76] = (byte)(var3[76] | 4);
         var3[87] = (byte)(var3[87] | 16);
         var3[92] = (byte)(var3[92] | 32);
         var3[102] = (byte)(var3[102] | 32);
         var3[109] = (byte)(var3[109] | 4);
         var3[118] = (byte)(var3[118] | 2);
         var3[125] = (byte)(var3[125] | 32);
      }

      if ((var2 & 4) != 0) {
         var3[6] = (byte)(var3[6] | 4);
         var3[23] = (byte)(var3[23] | 8);
         var3[30] = (byte)(var3[30] | 16);
         var3[39] = (byte)(var3[39] | 32);
         var3[45] = (byte)(var3[45] | 1);
         var3[54] = (byte)(var3[54] | 8);
         var3[70] = (byte)(var3[70] | 32);
         var3[77] = (byte)(var3[77] | 4);
         var3[86] = (byte)(var3[86] | 2);
         var3[92] = (byte)(var3[92] | 16);
         var3[101] = (byte)(var3[101] | 8);
         var3[116] = (byte)(var3[116] | 1);
         var3[125] = (byte)(var3[125] | 2);
      }

      if ((var2 & 2) != 0) {
         var3[4] = (byte)(var3[4] | 4);
         var3[13] = (byte)(var3[13] | 1);
         var3[22] = (byte)(var3[22] | 8);
         var3[36] = (byte)(var3[36] | 2);
         var3[47] = (byte)(var3[47] | 4);
         var3[53] = (byte)(var3[53] | 32);
         var3[63] = (byte)(var3[63] | 1);
         var3[69] = (byte)(var3[69] | 8);
         var3[84] = (byte)(var3[84] | 1);
         var3[94] = (byte)(var3[94] | 4);
         var3[100] = (byte)(var3[100] | 8);
         var3[117] = (byte)(var3[117] | 16);
         var3[127] = (byte)(var3[127] | 32);
      }

      var2 = var1[5];
      if ((var2 & 128) != 0) {
         var3[3] = (byte)(var3[3] | 32);
         var3[8] = (byte)(var3[8] | 16);
         var3[19] = (byte)(var3[19] | 4);
         var3[34] = (byte)(var3[34] | 1);
         var3[41] = (byte)(var3[41] | 16);
         var3[50] = (byte)(var3[50] | 2);
         var3[56] = (byte)(var3[56] | 2);
         var3[67] = (byte)(var3[67] | 1);
         var3[72] = (byte)(var3[72] | 1);
         var3[82] = (byte)(var3[82] | 4);
         var3[89] = (byte)(var3[89] | 32);
         var3[98] = (byte)(var3[98] | 32);
         var3[105] = (byte)(var3[105] | 8);
         var3[114] = (byte)(var3[114] | 8);
         var3[121] = (byte)(var3[121] | 1);
      }

      if ((var2 & 64) != 0) {
         var3[1] = (byte)(var3[1] | 32);
         var3[19] = (byte)(var3[19] | 2);
         var3[24] = (byte)(var3[24] | 32);
         var3[33] = (byte)(var3[33] | 1);
         var3[40] = (byte)(var3[40] | 16);
         var3[51] = (byte)(var3[51] | 4);
         var3[64] = (byte)(var3[64] | 8);
         var3[83] = (byte)(var3[83] | 8);
         var3[99] = (byte)(var3[99] | 1);
         var3[104] = (byte)(var3[104] | 1);
         var3[114] = (byte)(var3[114] | 4);
         var3[120] = (byte)(var3[120] | 4);
      }

      if ((var2 & 32) != 0) {
         var3[8] = (byte)(var3[8] | 2);
         var3[17] = (byte)(var3[17] | 4);
         var3[27] = (byte)(var3[27] | 16);
         var3[32] = (byte)(var3[32] | 4);
         var3[51] = (byte)(var3[51] | 2);
         var3[56] = (byte)(var3[56] | 32);
         var3[66] = (byte)(var3[66] | 8);
         var3[75] = (byte)(var3[75] | 32);
         var3[81] = (byte)(var3[81] | 2);
         var3[90] = (byte)(var3[90] | 16);
         var3[96] = (byte)(var3[96] | 8);
         var3[115] = (byte)(var3[115] | 8);
         var3[122] = (byte)(var3[122] | 2);
      }

      if ((var2 & 16) != 0) {
         var3[2] = (byte)(var3[2] | 16);
         var3[18] = (byte)(var3[18] | 1);
         var3[25] = (byte)(var3[25] | 16);
         var3[34] = (byte)(var3[34] | 2);
         var3[40] = (byte)(var3[40] | 2);
         var3[49] = (byte)(var3[49] | 4);
         var3[59] = (byte)(var3[59] | 16);
         var3[66] = (byte)(var3[66] | 4);
         var3[73] = (byte)(var3[73] | 32);
         var3[82] = (byte)(var3[82] | 32);
         var3[89] = (byte)(var3[89] | 8);
         var3[98] = (byte)(var3[98] | 8);
         var3[107] = (byte)(var3[107] | 32);
         var3[113] = (byte)(var3[113] | 2);
         var3[123] = (byte)(var3[123] | 4);
      }

      if ((var2 & 8) != 0) {
         var3[7] = (byte)(var3[7] | 1);
         var3[13] = (byte)(var3[13] | 8);
         var3[28] = (byte)(var3[28] | 1);
         var3[38] = (byte)(var3[38] | 4);
         var3[44] = (byte)(var3[44] | 8);
         var3[61] = (byte)(var3[61] | 16);
         var3[71] = (byte)(var3[71] | 32);
         var3[77] = (byte)(var3[77] | 1);
         var3[86] = (byte)(var3[86] | 8);
         var3[100] = (byte)(var3[100] | 2);
         var3[111] = (byte)(var3[111] | 4);
         var3[117] = (byte)(var3[117] | 32);
         var3[124] = (byte)(var3[124] | 16);
      }

      if ((var2 & 4) != 0) {
         var3[12] = (byte)(var3[12] | 8);
         var3[29] = (byte)(var3[29] | 16);
         var3[36] = (byte)(var3[36] | 4);
         var3[47] = (byte)(var3[47] | 16);
         var3[52] = (byte)(var3[52] | 32);
         var3[62] = (byte)(var3[62] | 32);
         var3[68] = (byte)(var3[68] | 2);
         var3[79] = (byte)(var3[79] | 4);
         var3[85] = (byte)(var3[85] | 32);
         var3[95] = (byte)(var3[95] | 1);
         var3[102] = (byte)(var3[102] | 1);
         var3[111] = (byte)(var3[111] | 2);
         var3[117] = (byte)(var3[117] | 2);
         var3[126] = (byte)(var3[126] | 4);
      }

      if ((var2 & 2) != 0) {
         var3[5] = (byte)(var3[5] | 1);
         var3[15] = (byte)(var3[15] | 16);
         var3[20] = (byte)(var3[20] | 32);
         var3[30] = (byte)(var3[30] | 32);
         var3[37] = (byte)(var3[37] | 4);
         var3[46] = (byte)(var3[46] | 2);
         var3[52] = (byte)(var3[52] | 16);
         var3[61] = (byte)(var3[61] | 8);
         var3[70] = (byte)(var3[70] | 1);
         var3[79] = (byte)(var3[79] | 2);
         var3[85] = (byte)(var3[85] | 2);
         var3[103] = (byte)(var3[103] | 8);
         var3[110] = (byte)(var3[110] | 16);
         var3[119] = (byte)(var3[119] | 32);
         var3[124] = (byte)(var3[124] | 4);
      }

      var2 = var1[6];
      if ((var2 & 128) != 0) {
         var3[0] = (byte)(var3[0] | 16);
         var3[9] = (byte)(var3[9] | 2);
         var3[18] = (byte)(var3[18] | 16);
         var3[24] = (byte)(var3[24] | 8);
         var3[43] = (byte)(var3[43] | 8);
         var3[59] = (byte)(var3[59] | 1);
         var3[65] = (byte)(var3[65] | 4);
         var3[75] = (byte)(var3[75] | 16);
         var3[80] = (byte)(var3[80] | 4);
         var3[99] = (byte)(var3[99] | 2);
         var3[104] = (byte)(var3[104] | 32);
         var3[113] = (byte)(var3[113] | 1);
         var3[123] = (byte)(var3[123] | 32);
      }

      if ((var2 & 64) != 0) {
         var3[10] = (byte)(var3[10] | 32);
         var3[17] = (byte)(var3[17] | 8);
         var3[26] = (byte)(var3[26] | 8);
         var3[35] = (byte)(var3[35] | 32);
         var3[41] = (byte)(var3[41] | 2);
         var3[50] = (byte)(var3[50] | 16);
         var3[56] = (byte)(var3[56] | 8);
         var3[66] = (byte)(var3[66] | 1);
         var3[73] = (byte)(var3[73] | 16);
         var3[82] = (byte)(var3[82] | 2);
         var3[88] = (byte)(var3[88] | 2);
         var3[97] = (byte)(var3[97] | 4);
         var3[107] = (byte)(var3[107] | 16);
         var3[112] = (byte)(var3[112] | 4);
         var3[121] = (byte)(var3[121] | 32);
      }

      if ((var2 & 32) != 0) {
         var3[0] = (byte)(var3[0] | 2);
         var3[11] = (byte)(var3[11] | 1);
         var3[16] = (byte)(var3[16] | 1);
         var3[26] = (byte)(var3[26] | 4);
         var3[33] = (byte)(var3[33] | 32);
         var3[42] = (byte)(var3[42] | 32);
         var3[49] = (byte)(var3[49] | 8);
         var3[58] = (byte)(var3[58] | 8);
         var3[65] = (byte)(var3[65] | 1);
         var3[72] = (byte)(var3[72] | 16);
         var3[83] = (byte)(var3[83] | 4);
         var3[98] = (byte)(var3[98] | 1);
         var3[105] = (byte)(var3[105] | 16);
         var3[114] = (byte)(var3[114] | 2);
      }

      if ((var2 & 16) != 0) {
         var3[8] = (byte)(var3[8] | 8);
         var3[27] = (byte)(var3[27] | 8);
         var3[43] = (byte)(var3[43] | 1);
         var3[48] = (byte)(var3[48] | 1);
         var3[58] = (byte)(var3[58] | 4);
         var3[64] = (byte)(var3[64] | 4);
         var3[83] = (byte)(var3[83] | 2);
         var3[88] = (byte)(var3[88] | 32);
         var3[97] = (byte)(var3[97] | 1);
         var3[104] = (byte)(var3[104] | 16);
         var3[115] = (byte)(var3[115] | 4);
         var3[122] = (byte)(var3[122] | 16);
      }

      if ((var2 & 8) != 0) {
         var3[5] = (byte)(var3[5] | 8);
         var3[14] = (byte)(var3[14] | 1);
         var3[23] = (byte)(var3[23] | 2);
         var3[29] = (byte)(var3[29] | 2);
         var3[47] = (byte)(var3[47] | 8);
         var3[54] = (byte)(var3[54] | 16);
         var3[63] = (byte)(var3[63] | 32);
         var3[68] = (byte)(var3[68] | 4);
         var3[79] = (byte)(var3[79] | 16);
         var3[84] = (byte)(var3[84] | 32);
         var3[94] = (byte)(var3[94] | 32);
         var3[101] = (byte)(var3[101] | 4);
         var3[110] = (byte)(var3[110] | 2);
         var3[116] = (byte)(var3[116] | 16);
         var3[127] = (byte)(var3[127] | 1);
      }

      if ((var2 & 4) != 0) {
         var3[4] = (byte)(var3[4] | 8);
         var3[15] = (byte)(var3[15] | 8);
         var3[22] = (byte)(var3[22] | 16);
         var3[31] = (byte)(var3[31] | 32);
         var3[37] = (byte)(var3[37] | 1);
         var3[46] = (byte)(var3[46] | 8);
         var3[60] = (byte)(var3[60] | 2);
         var3[69] = (byte)(var3[69] | 4);
         var3[78] = (byte)(var3[78] | 2);
         var3[84] = (byte)(var3[84] | 16);
         var3[93] = (byte)(var3[93] | 8);
         var3[108] = (byte)(var3[108] | 1);
         var3[118] = (byte)(var3[118] | 4);
      }

      if ((var2 & 2) != 0) {
         var3[7] = (byte)(var3[7] | 16);
         var3[14] = (byte)(var3[14] | 8);
         var3[28] = (byte)(var3[28] | 2);
         var3[39] = (byte)(var3[39] | 4);
         var3[45] = (byte)(var3[45] | 32);
         var3[55] = (byte)(var3[55] | 1);
         var3[62] = (byte)(var3[62] | 1);
         var3[76] = (byte)(var3[76] | 1);
         var3[86] = (byte)(var3[86] | 4);
         var3[92] = (byte)(var3[92] | 8);
         var3[109] = (byte)(var3[109] | 16);
         var3[116] = (byte)(var3[116] | 4);
         var3[125] = (byte)(var3[125] | 1);
      }

      var2 = var1[7];
      if ((var2 & 128) != 0) {
         var3[1] = (byte)(var3[1] | 2);
         var3[11] = (byte)(var3[11] | 4);
         var3[26] = (byte)(var3[26] | 1);
         var3[33] = (byte)(var3[33] | 16);
         var3[42] = (byte)(var3[42] | 2);
         var3[48] = (byte)(var3[48] | 2);
         var3[57] = (byte)(var3[57] | 4);
         var3[64] = (byte)(var3[64] | 1);
         var3[74] = (byte)(var3[74] | 4);
         var3[81] = (byte)(var3[81] | 32);
         var3[90] = (byte)(var3[90] | 32);
         var3[97] = (byte)(var3[97] | 8);
         var3[106] = (byte)(var3[106] | 8);
         var3[115] = (byte)(var3[115] | 32);
         var3[120] = (byte)(var3[120] | 16);
      }

      if ((var2 & 64) != 0) {
         var3[2] = (byte)(var3[2] | 32);
         var3[11] = (byte)(var3[11] | 2);
         var3[16] = (byte)(var3[16] | 32);
         var3[25] = (byte)(var3[25] | 1);
         var3[32] = (byte)(var3[32] | 16);
         var3[43] = (byte)(var3[43] | 4);
         var3[58] = (byte)(var3[58] | 1);
         var3[75] = (byte)(var3[75] | 8);
         var3[91] = (byte)(var3[91] | 1);
         var3[96] = (byte)(var3[96] | 1);
         var3[106] = (byte)(var3[106] | 4);
         var3[113] = (byte)(var3[113] | 32);
      }

      if ((var2 & 32) != 0) {
         var3[3] = (byte)(var3[3] | 1);
         var3[9] = (byte)(var3[9] | 4);
         var3[19] = (byte)(var3[19] | 16);
         var3[24] = (byte)(var3[24] | 4);
         var3[43] = (byte)(var3[43] | 2);
         var3[48] = (byte)(var3[48] | 32);
         var3[57] = (byte)(var3[57] | 1);
         var3[67] = (byte)(var3[67] | 32);
         var3[73] = (byte)(var3[73] | 2);
         var3[82] = (byte)(var3[82] | 16);
         var3[88] = (byte)(var3[88] | 8);
         var3[107] = (byte)(var3[107] | 8);
         var3[120] = (byte)(var3[120] | 2);
      }

      if ((var2 & 16) != 0) {
         var3[0] = (byte)(var3[0] | 8);
         var3[10] = (byte)(var3[10] | 1);
         var3[17] = (byte)(var3[17] | 16);
         var3[26] = (byte)(var3[26] | 2);
         var3[32] = (byte)(var3[32] | 2);
         var3[41] = (byte)(var3[41] | 4);
         var3[51] = (byte)(var3[51] | 16);
         var3[56] = (byte)(var3[56] | 4);
         var3[65] = (byte)(var3[65] | 32);
         var3[74] = (byte)(var3[74] | 32);
         var3[81] = (byte)(var3[81] | 8);
         var3[90] = (byte)(var3[90] | 8);
         var3[99] = (byte)(var3[99] | 32);
         var3[105] = (byte)(var3[105] | 2);
         var3[114] = (byte)(var3[114] | 16);
      }

      if ((var2 & 8) != 0) {
         var3[6] = (byte)(var3[6] | 1);
         var3[20] = (byte)(var3[20] | 1);
         var3[30] = (byte)(var3[30] | 4);
         var3[36] = (byte)(var3[36] | 8);
         var3[53] = (byte)(var3[53] | 16);
         var3[60] = (byte)(var3[60] | 4);
         var3[69] = (byte)(var3[69] | 1);
         var3[78] = (byte)(var3[78] | 8);
         var3[92] = (byte)(var3[92] | 2);
         var3[103] = (byte)(var3[103] | 4);
         var3[109] = (byte)(var3[109] | 32);
         var3[119] = (byte)(var3[119] | 1);
         var3[125] = (byte)(var3[125] | 8);
      }

      if ((var2 & 4) != 0) {
         var3[7] = (byte)(var3[7] | 8);
         var3[21] = (byte)(var3[21] | 16);
         var3[28] = (byte)(var3[28] | 4);
         var3[39] = (byte)(var3[39] | 16);
         var3[44] = (byte)(var3[44] | 32);
         var3[54] = (byte)(var3[54] | 32);
         var3[61] = (byte)(var3[61] | 4);
         var3[71] = (byte)(var3[71] | 4);
         var3[77] = (byte)(var3[77] | 32);
         var3[87] = (byte)(var3[87] | 1);
         var3[94] = (byte)(var3[94] | 1);
         var3[103] = (byte)(var3[103] | 2);
         var3[109] = (byte)(var3[109] | 2);
         var3[124] = (byte)(var3[124] | 8);
      }

      if ((var2 & 2) != 0) {
         var3[6] = (byte)(var3[6] | 8);
         var3[12] = (byte)(var3[12] | 32);
         var3[22] = (byte)(var3[22] | 32);
         var3[29] = (byte)(var3[29] | 4);
         var3[38] = (byte)(var3[38] | 2);
         var3[44] = (byte)(var3[44] | 16);
         var3[53] = (byte)(var3[53] | 8);
         var3[71] = (byte)(var3[71] | 2);
         var3[77] = (byte)(var3[77] | 2);
         var3[95] = (byte)(var3[95] | 8);
         var3[102] = (byte)(var3[102] | 16);
         var3[111] = (byte)(var3[111] | 32);
         var3[117] = (byte)(var3[117] | 1);
         var3[127] = (byte)(var3[127] | 16);
      }

      this.expandedKey = var3;
   }
}
