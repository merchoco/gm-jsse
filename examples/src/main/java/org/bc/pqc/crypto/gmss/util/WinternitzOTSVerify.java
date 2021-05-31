package org.bc.pqc.crypto.gmss.util;

import org.bc.crypto.Digest;

public class WinternitzOTSVerify {
   private Digest messDigestOTS;
   private int w;

   public WinternitzOTSVerify(Digest var1, int var2) {
      this.w = var2;
      this.messDigestOTS = var1;
   }

   public int getSignatureLength() {
      int var1 = this.messDigestOTS.getDigestSize();
      int var2 = ((var1 << 3) + (this.w - 1)) / this.w;
      int var3 = this.getLog((var2 << this.w) + 1);
      var2 += (var3 + this.w - 1) / this.w;
      return var1 * var2;
   }

   public byte[] Verify(byte[] var1, byte[] var2) {
      int var3 = this.messDigestOTS.getDigestSize();
      byte[] var4 = new byte[var3];
      this.messDigestOTS.update(var1, 0, var1.length);
      var4 = new byte[this.messDigestOTS.getDigestSize()];
      this.messDigestOTS.doFinal(var4, 0);
      int var5 = ((var3 << 3) + (this.w - 1)) / this.w;
      int var6 = this.getLog((var5 << this.w) + 1);
      int var7 = var5 + (var6 + this.w - 1) / this.w;
      int var8 = var3 * var7;
      if (var8 != var2.length) {
         return null;
      } else {
         byte[] var9 = new byte[var8];
         int var10 = 0;
         int var11 = 0;
         int var12;
         int var13;
         int var14;
         byte[] var15;
         if (8 % this.w == 0) {
            var13 = 8 / this.w;
            var14 = (1 << this.w) - 1;
            var15 = new byte[var3];

            int var16;
            for(var16 = 0; var16 < var4.length; ++var16) {
               for(int var17 = 0; var17 < var13; ++var17) {
                  var12 = var4[var16] & var14;
                  var10 += var12;
                  System.arraycopy(var2, var11 * var3, var15, 0, var3);

                  while(var12 < var14) {
                     this.messDigestOTS.update(var15, 0, var15.length);
                     var15 = new byte[this.messDigestOTS.getDigestSize()];
                     this.messDigestOTS.doFinal(var15, 0);
                     ++var12;
                  }

                  System.arraycopy(var15, 0, var9, var11 * var3, var3);
                  var4[var16] = (byte)(var4[var16] >>> this.w);
                  ++var11;
               }
            }

            var10 = (var5 << this.w) - var10;

            for(var16 = 0; var16 < var6; var16 += this.w) {
               var12 = var10 & var14;
               System.arraycopy(var2, var11 * var3, var15, 0, var3);

               while(var12 < var14) {
                  this.messDigestOTS.update(var15, 0, var15.length);
                  var15 = new byte[this.messDigestOTS.getDigestSize()];
                  this.messDigestOTS.doFinal(var15, 0);
                  ++var12;
               }

               System.arraycopy(var15, 0, var9, var11 * var3, var3);
               var10 >>>= this.w;
               ++var11;
            }
         } else {
            int var20;
            long var27;
            if (this.w < 8) {
               var13 = var3 / this.w;
               var14 = (1 << this.w) - 1;
               var15 = new byte[var3];
               int var18 = 0;

               int var19;
               for(var19 = 0; var19 < var13; ++var19) {
                  var27 = 0L;

                  for(var20 = 0; var20 < this.w; ++var20) {
                     var27 ^= (long)((var4[var18] & 255) << (var20 << 3));
                     ++var18;
                  }

                  for(var20 = 0; var20 < 8; ++var20) {
                     var12 = (int)(var27 & (long)var14);
                     var10 += var12;
                     System.arraycopy(var2, var11 * var3, var15, 0, var3);

                     while(var12 < var14) {
                        this.messDigestOTS.update(var15, 0, var15.length);
                        var15 = new byte[this.messDigestOTS.getDigestSize()];
                        this.messDigestOTS.doFinal(var15, 0);
                        ++var12;
                     }

                     System.arraycopy(var15, 0, var9, var11 * var3, var3);
                     var27 >>>= this.w;
                     ++var11;
                  }
               }

               var13 = var3 % this.w;
               var27 = 0L;

               for(var19 = 0; var19 < var13; ++var19) {
                  var27 ^= (long)((var4[var18] & 255) << (var19 << 3));
                  ++var18;
               }

               var13 <<= 3;

               for(var19 = 0; var19 < var13; var19 += this.w) {
                  var12 = (int)(var27 & (long)var14);
                  var10 += var12;
                  System.arraycopy(var2, var11 * var3, var15, 0, var3);

                  while(var12 < var14) {
                     this.messDigestOTS.update(var15, 0, var15.length);
                     var15 = new byte[this.messDigestOTS.getDigestSize()];
                     this.messDigestOTS.doFinal(var15, 0);
                     ++var12;
                  }

                  System.arraycopy(var15, 0, var9, var11 * var3, var3);
                  var27 >>>= this.w;
                  ++var11;
               }

               var10 = (var5 << this.w) - var10;

               for(var19 = 0; var19 < var6; var19 += this.w) {
                  var12 = var10 & var14;
                  System.arraycopy(var2, var11 * var3, var15, 0, var3);

                  while(var12 < var14) {
                     this.messDigestOTS.update(var15, 0, var15.length);
                     var15 = new byte[this.messDigestOTS.getDigestSize()];
                     this.messDigestOTS.doFinal(var15, 0);
                     ++var12;
                  }

                  System.arraycopy(var15, 0, var9, var11 * var3, var3);
                  var10 >>>= this.w;
                  ++var11;
               }
            } else if (this.w < 57) {
               var13 = (var3 << 3) - this.w;
               var14 = (1 << this.w) - 1;
               var15 = new byte[var3];

               int var21;
               int var23;
               int var24;
               int var25;
               long var28;
               for(var20 = 0; var20 <= var13; ++var11) {
                  var21 = var20 >>> 3;
                  var23 = var20 % 8;
                  var20 += this.w;
                  int var22 = var20 + 7 >>> 3;
                  var27 = 0L;
                  var24 = 0;

                  for(var25 = var21; var25 < var22; ++var25) {
                     var27 ^= (long)((var4[var25] & 255) << (var24 << 3));
                     ++var24;
                  }

                  var27 >>>= var23;
                  var28 = var27 & (long)var14;
                  var10 = (int)((long)var10 + var28);
                  System.arraycopy(var2, var11 * var3, var15, 0, var3);

                  while(var28 < (long)var14) {
                     this.messDigestOTS.update(var15, 0, var15.length);
                     var15 = new byte[this.messDigestOTS.getDigestSize()];
                     this.messDigestOTS.doFinal(var15, 0);
                     ++var28;
                  }

                  System.arraycopy(var15, 0, var9, var11 * var3, var3);
               }

               var21 = var20 >>> 3;
               if (var21 < var3) {
                  var23 = var20 % 8;
                  var27 = 0L;
                  var24 = 0;

                  for(var25 = var21; var25 < var3; ++var25) {
                     var27 ^= (long)((var4[var25] & 255) << (var24 << 3));
                     ++var24;
                  }

                  var27 >>>= var23;
                  var28 = var27 & (long)var14;
                  var10 = (int)((long)var10 + var28);
                  System.arraycopy(var2, var11 * var3, var15, 0, var3);

                  while(var28 < (long)var14) {
                     this.messDigestOTS.update(var15, 0, var15.length);
                     var15 = new byte[this.messDigestOTS.getDigestSize()];
                     this.messDigestOTS.doFinal(var15, 0);
                     ++var28;
                  }

                  System.arraycopy(var15, 0, var9, var11 * var3, var3);
                  ++var11;
               }

               var10 = (var5 << this.w) - var10;

               for(var25 = 0; var25 < var6; var25 += this.w) {
                  var28 = (long)(var10 & var14);
                  System.arraycopy(var2, var11 * var3, var15, 0, var3);

                  while(var28 < (long)var14) {
                     this.messDigestOTS.update(var15, 0, var15.length);
                     var15 = new byte[this.messDigestOTS.getDigestSize()];
                     this.messDigestOTS.doFinal(var15, 0);
                     ++var28;
                  }

                  System.arraycopy(var15, 0, var9, var11 * var3, var3);
                  var10 >>>= this.w;
                  ++var11;
               }
            }
         }

         byte[] var26 = new byte[var3];
         this.messDigestOTS.update(var9, 0, var9.length);
         var26 = new byte[this.messDigestOTS.getDigestSize()];
         this.messDigestOTS.doFinal(var26, 0);
         return var26;
      }
   }

   public int getLog(int var1) {
      int var2 = 1;

      for(int var3 = 2; var3 < var1; ++var2) {
         var3 <<= 1;
      }

      return var2;
   }
}
