package org.bc.math.ec;

import java.math.BigInteger;

class WTauNafMultiplier implements ECMultiplier {
   public ECPoint multiply(ECPoint var1, BigInteger var2, PreCompInfo var3) {
      if (!(var1 instanceof ECPoint.F2m)) {
         throw new IllegalArgumentException("Only ECPoint.F2m can be used in WTauNafMultiplier");
      } else {
         ECPoint.F2m var4 = (ECPoint.F2m)var1;
         ECCurve.F2m var5 = (ECCurve.F2m)var4.getCurve();
         int var6 = var5.getM();
         byte var7 = var5.getA().toBigInteger().byteValue();
         byte var8 = var5.getMu();
         BigInteger[] var9 = var5.getSi();
         ZTauElement var10 = Tnaf.partModReduction(var2, var6, var7, var9, var8, (byte)10);
         return this.multiplyWTnaf(var4, var10, var3, var7, var8);
      }
   }

   private ECPoint.F2m multiplyWTnaf(ECPoint.F2m var1, ZTauElement var2, PreCompInfo var3, byte var4, byte var5) {
      ZTauElement[] var6;
      if (var4 == 0) {
         var6 = Tnaf.alpha0;
      } else {
         var6 = Tnaf.alpha1;
      }

      BigInteger var7 = Tnaf.getTw(var5, 4);
      byte[] var8 = Tnaf.tauAdicWNaf(var5, var2, (byte)4, BigInteger.valueOf(16L), var7, var6);
      return multiplyFromWTnaf(var1, var8, var3);
   }

   private static ECPoint.F2m multiplyFromWTnaf(ECPoint.F2m var0, byte[] var1, PreCompInfo var2) {
      ECCurve.F2m var3 = (ECCurve.F2m)var0.getCurve();
      byte var4 = var3.getA().toBigInteger().byteValue();
      ECPoint.F2m[] var5;
      if (var2 != null && var2 instanceof WTauNafPreCompInfo) {
         var5 = ((WTauNafPreCompInfo)var2).getPreComp();
      } else {
         var5 = Tnaf.getPreComp(var0, var4);
         var0.setPreCompInfo(new WTauNafPreCompInfo(var5));
      }

      ECPoint.F2m var6 = (ECPoint.F2m)var0.getCurve().getInfinity();

      for(int var7 = var1.length - 1; var7 >= 0; --var7) {
         var6 = Tnaf.tau(var6);
         if (var1[var7] != 0) {
            if (var1[var7] > 0) {
               var6 = var6.addSimple(var5[var1[var7]]);
            } else {
               var6 = var6.subtractSimple(var5[-var1[var7]]);
            }
         }
      }

      return var6;
   }
}
