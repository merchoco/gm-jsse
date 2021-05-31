package org.bc.math.ec;

class WTauNafPreCompInfo implements PreCompInfo {
   private ECPoint.F2m[] preComp = null;

   WTauNafPreCompInfo(ECPoint.F2m[] var1) {
      this.preComp = var1;
   }

   protected ECPoint.F2m[] getPreComp() {
      return this.preComp;
   }
}
