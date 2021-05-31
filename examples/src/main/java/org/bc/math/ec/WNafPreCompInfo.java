package org.bc.math.ec;

class WNafPreCompInfo implements PreCompInfo {
   private ECPoint[] preComp = null;
   private ECPoint twiceP = null;

   protected ECPoint[] getPreComp() {
      return this.preComp;
   }

   protected void setPreComp(ECPoint[] var1) {
      this.preComp = var1;
   }

   protected ECPoint getTwiceP() {
      return this.twiceP;
   }

   protected void setTwiceP(ECPoint var1) {
      this.twiceP = var1;
   }
}
