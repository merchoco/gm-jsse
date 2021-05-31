package org.bc.pqc.crypto.gmss.util;

import org.bc.crypto.Digest;

public class WinternitzOTSignature {
   private Digest messDigestOTS;
   private int mdsize;
   private int keysize;
   private byte[][] privateKeyOTS;
   private int w;
   private GMSSRandom gmssRandom;
   private int messagesize;
   private int checksumsize;

   public WinternitzOTSignature(byte[] var1, Digest var2, int var3) {
      this.w = var3;
      this.messDigestOTS = var2;
      this.gmssRandom = new GMSSRandom(this.messDigestOTS);
      this.mdsize = this.messDigestOTS.getDigestSize();
      int var4 = this.mdsize << 3;
      this.messagesize = (int)Math.ceil((double)var4 / (double)var3);
      this.checksumsize = this.getLog((this.messagesize << var3) + 1);
      this.keysize = this.messagesize + (int)Math.ceil((double)this.checksumsize / (double)var3);
      this.privateKeyOTS = new byte[this.keysize][this.mdsize];
      byte[] var5 = new byte[this.mdsize];
      System.arraycopy(var1, 0, var5, 0, var5.length);

      for(int var6 = 0; var6 < this.keysize; ++var6) {
         this.privateKeyOTS[var6] = this.gmssRandom.nextSeed(var5);
      }

   }

   public byte[][] getPrivateKey() {
      return this.privateKeyOTS;
   }

   public byte[] getPublicKey() {
      byte[] var1 = new byte[this.keysize * this.mdsize];
      byte[] var2 = new byte[this.mdsize];
      int var3 = 1 << this.w;

      for(int var4 = 0; var4 < this.keysize; ++var4) {
         this.messDigestOTS.update(this.privateKeyOTS[var4], 0, this.privateKeyOTS[var4].length);
         var2 = new byte[this.messDigestOTS.getDigestSize()];
         this.messDigestOTS.doFinal(var2, 0);

         for(int var5 = 2; var5 < var3; ++var5) {
            this.messDigestOTS.update(var2, 0, var2.length);
            var2 = new byte[this.messDigestOTS.getDigestSize()];
            this.messDigestOTS.doFinal(var2, 0);
         }

         System.arraycopy(var2, 0, var1, this.mdsize * var4, this.mdsize);
      }

      this.messDigestOTS.update(var1, 0, var1.length);
      byte[] var6 = new byte[this.messDigestOTS.getDigestSize()];
      this.messDigestOTS.doFinal(var6, 0);
      return var6;
   }

   public byte[] getSignature(byte[] var1) {
      byte[] var2 = new byte[this.keysize * this.mdsize];
      byte[] var3 = new byte[this.mdsize];
      int var4 = 0;
      int var5 = 0;
      boolean var6 = false;
      this.messDigestOTS.update(var1, 0, var1.length);
      var3 = new byte[this.messDigestOTS.getDigestSize()];
      this.messDigestOTS.doFinal(var3, 0);
      int var7;
      int var8;
      byte[] var9;
      int var20;
      if (8 % this.w == 0) {
         var7 = 8 / this.w;
         var8 = (1 << this.w) - 1;
         var9 = new byte[this.mdsize];

         int var10;
         for(var10 = 0; var10 < var3.length; ++var10) {
            for(int var11 = 0; var11 < var7; ++var11) {
               var20 = var3[var10] & var8;
               var5 += var20;
               System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

               while(var20 > 0) {
                  this.messDigestOTS.update(var9, 0, var9.length);
                  var9 = new byte[this.messDigestOTS.getDigestSize()];
                  this.messDigestOTS.doFinal(var9, 0);
                  --var20;
               }

               System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
               var3[var10] = (byte)(var3[var10] >>> this.w);
               ++var4;
            }
         }

         var5 = (this.messagesize << this.w) - var5;

         for(var10 = 0; var10 < this.checksumsize; var10 += this.w) {
            var20 = var5 & var8;
            System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

            while(var20 > 0) {
               this.messDigestOTS.update(var9, 0, var9.length);
               var9 = new byte[this.messDigestOTS.getDigestSize()];
               this.messDigestOTS.doFinal(var9, 0);
               --var20;
            }

            System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
            var5 >>>= this.w;
            ++var4;
         }
      } else {
         int var14;
         long var21;
         if (this.w < 8) {
            var7 = this.mdsize / this.w;
            var8 = (1 << this.w) - 1;
            var9 = new byte[this.mdsize];
            int var12 = 0;

            int var13;
            for(var13 = 0; var13 < var7; ++var13) {
               var21 = 0L;

               for(var14 = 0; var14 < this.w; ++var14) {
                  var21 ^= (long)((var3[var12] & 255) << (var14 << 3));
                  ++var12;
               }

               for(var14 = 0; var14 < 8; ++var14) {
                  var20 = (int)(var21 & (long)var8);
                  var5 += var20;
                  System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

                  while(var20 > 0) {
                     this.messDigestOTS.update(var9, 0, var9.length);
                     var9 = new byte[this.messDigestOTS.getDigestSize()];
                     this.messDigestOTS.doFinal(var9, 0);
                     --var20;
                  }

                  System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
                  var21 >>>= this.w;
                  ++var4;
               }
            }

            var7 = this.mdsize % this.w;
            var21 = 0L;

            for(var13 = 0; var13 < var7; ++var13) {
               var21 ^= (long)((var3[var12] & 255) << (var13 << 3));
               ++var12;
            }

            var7 <<= 3;

            for(var13 = 0; var13 < var7; var13 += this.w) {
               var20 = (int)(var21 & (long)var8);
               var5 += var20;
               System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

               while(var20 > 0) {
                  this.messDigestOTS.update(var9, 0, var9.length);
                  var9 = new byte[this.messDigestOTS.getDigestSize()];
                  this.messDigestOTS.doFinal(var9, 0);
                  --var20;
               }

               System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
               var21 >>>= this.w;
               ++var4;
            }

            var5 = (this.messagesize << this.w) - var5;

            for(var13 = 0; var13 < this.checksumsize; var13 += this.w) {
               var20 = var5 & var8;
               System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

               while(var20 > 0) {
                  this.messDigestOTS.update(var9, 0, var9.length);
                  var9 = new byte[this.messDigestOTS.getDigestSize()];
                  this.messDigestOTS.doFinal(var9, 0);
                  --var20;
               }

               System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
               var5 >>>= this.w;
               ++var4;
            }
         } else if (this.w < 57) {
            var7 = (this.mdsize << 3) - this.w;
            var8 = (1 << this.w) - 1;
            var9 = new byte[this.mdsize];

            int var15;
            int var17;
            int var18;
            int var19;
            long var22;
            for(var14 = 0; var14 <= var7; ++var4) {
               var15 = var14 >>> 3;
               var17 = var14 % 8;
               var14 += this.w;
               int var16 = var14 + 7 >>> 3;
               var21 = 0L;
               var18 = 0;

               for(var19 = var15; var19 < var16; ++var19) {
                  var21 ^= (long)((var3[var19] & 255) << (var18 << 3));
                  ++var18;
               }

               var21 >>>= var17;
               var22 = var21 & (long)var8;
               var5 = (int)((long)var5 + var22);
               System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

               while(var22 > 0L) {
                  this.messDigestOTS.update(var9, 0, var9.length);
                  var9 = new byte[this.messDigestOTS.getDigestSize()];
                  this.messDigestOTS.doFinal(var9, 0);
                  --var22;
               }

               System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
            }

            var15 = var14 >>> 3;
            if (var15 < this.mdsize) {
               var17 = var14 % 8;
               var21 = 0L;
               var18 = 0;

               for(var19 = var15; var19 < this.mdsize; ++var19) {
                  var21 ^= (long)((var3[var19] & 255) << (var18 << 3));
                  ++var18;
               }

               var21 >>>= var17;
               var22 = var21 & (long)var8;
               var5 = (int)((long)var5 + var22);
               System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

               while(var22 > 0L) {
                  this.messDigestOTS.update(var9, 0, var9.length);
                  var9 = new byte[this.messDigestOTS.getDigestSize()];
                  this.messDigestOTS.doFinal(var9, 0);
                  --var22;
               }

               System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
               ++var4;
            }

            var5 = (this.messagesize << this.w) - var5;

            for(var19 = 0; var19 < this.checksumsize; var19 += this.w) {
               var22 = (long)(var5 & var8);
               System.arraycopy(this.privateKeyOTS[var4], 0, var9, 0, this.mdsize);

               while(var22 > 0L) {
                  this.messDigestOTS.update(var9, 0, var9.length);
                  var9 = new byte[this.messDigestOTS.getDigestSize()];
                  this.messDigestOTS.doFinal(var9, 0);
                  --var22;
               }

               System.arraycopy(var9, 0, var2, var4 * this.mdsize, this.mdsize);
               var5 >>>= this.w;
               ++var4;
            }
         }
      }

      return var2;
   }

   public int getLog(int var1) {
      int var2 = 1;

      for(int var3 = 2; var3 < var1; ++var2) {
         var3 <<= 1;
      }

      return var2;
   }
}
