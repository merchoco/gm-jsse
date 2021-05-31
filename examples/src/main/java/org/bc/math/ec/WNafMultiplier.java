package org.bc.math.ec;

import java.math.BigInteger;

class WNafMultiplier implements ECMultiplier {
   public byte[] windowNaf(byte var1, BigInteger var2) {
      byte[] var3 = new byte[var2.bitLength() + 1];
      short var4 = (short)(1 << var1);
      BigInteger var5 = BigInteger.valueOf((long)var4);
      int var6 = 0;

      int var7;
      for(var7 = 0; var2.signum() > 0; ++var6) {
         if (var2.testBit(0)) {
            BigInteger var8 = var2.mod(var5);
            if (var8.testBit(var1 - 1)) {
               var3[var6] = (byte)(var8.intValue() - var4);
            } else {
               var3[var6] = (byte)var8.intValue();
            }

            var2 = var2.subtract(BigInteger.valueOf((long)var3[var6]));
            var7 = var6;
         } else {
            var3[var6] = 0;
         }

         var2 = var2.shiftRight(1);
      }

      ++var7;
      byte[] var9 = new byte[var7];
      System.arraycopy(var3, 0, var9, 0, var7);
      return var9;
   }

   public ECPoint multiply(ECPoint var1, BigInteger var2, PreCompInfo var3) {
      WNafPreCompInfo var4;
      if (var3 != null && var3 instanceof WNafPreCompInfo) {
         var4 = (WNafPreCompInfo)var3;
      } else {
         var4 = new WNafPreCompInfo();
      }

      int var5 = var2.bitLength();
      byte var6;
      byte var7;
      if (var5 < 13) {
         var6 = 2;
         var7 = 1;
      } else if (var5 < 41) {
         var6 = 3;
         var7 = 2;
      } else if (var5 < 121) {
         var6 = 4;
         var7 = 4;
      } else if (var5 < 337) {
         var6 = 5;
         var7 = 8;
      } else if (var5 < 897) {
         var6 = 6;
         var7 = 16;
      } else if (var5 < 2305) {
         var6 = 7;
         var7 = 32;
      } else {
         var6 = 8;
         var7 = 127;
      }

      int var8 = 1;
      ECPoint[] var9 = var4.getPreComp();
      ECPoint var10 = var4.getTwiceP();
      if (var9 == null) {
         var9 = new ECPoint[]{var1};
      } else {
         var8 = var9.length;
      }

      if (var10 == null) {
         var10 = var1.twice();
      }

      int var12;
      if (var8 < var7) {
         ECPoint[] var11 = var9;
         var9 = new ECPoint[var7];
         System.arraycopy(var11, 0, var9, 0, var8);

         for(var12 = var8; var12 < var7; ++var12) {
            var9[var12] = var10.add(var9[var12 - 1]);
         }
      }

      byte[] var15 = this.windowNaf(var6, var2);
      var12 = var15.length;
      ECPoint var13 = var1.getCurve().getInfinity();

      for(int var14 = var12 - 1; var14 >= 0; --var14) {
         var13 = var13.twice();
         if (var15[var14] != 0) {
            if (var15[var14] > 0) {
               var13 = var13.add(var9[(var15[var14] - 1) / 2]);
            } else {
               var13 = var13.subtract(var9[(-var15[var14] - 1) / 2]);
            }
         }
      }

      var4.setPreComp(var9);
      var4.setTwiceP(var10);
      var1.setPreCompInfo(var4);
      return var13;
   }
}
