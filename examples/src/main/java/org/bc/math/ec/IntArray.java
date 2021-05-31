package org.bc.math.ec;

import java.math.BigInteger;
import org.bc.util.Arrays;

class IntArray {
   private int[] m_ints;

   public IntArray(int var1) {
      this.m_ints = new int[var1];
   }

   public IntArray(int[] var1) {
      this.m_ints = var1;
   }

   public IntArray(BigInteger var1) {
      this(var1, 0);
   }

   public IntArray(BigInteger var1, int var2) {
      if (var1.signum() == -1) {
         throw new IllegalArgumentException("Only positive Integers allowed");
      } else if (var1.equals(ECConstants.ZERO)) {
         this.m_ints = new int[1];
      } else {
         byte[] var3 = var1.toByteArray();
         int var4 = var3.length;
         byte var5 = 0;
         if (var3[0] == 0) {
            --var4;
            var5 = 1;
         }

         int var6 = (var4 + 3) / 4;
         if (var6 < var2) {
            this.m_ints = new int[var2];
         } else {
            this.m_ints = new int[var6];
         }

         int var7 = var6 - 1;
         int var8 = var4 % 4 + var5;
         int var9 = 0;
         int var10 = var5;
         int var11;
         if (var5 < var8) {
            while(var10 < var8) {
               var9 <<= 8;
               var11 = var3[var10];
               if (var11 < 0) {
                  var11 += 256;
               }

               var9 |= var11;
               ++var10;
            }

            this.m_ints[var7--] = var9;
         }

         while(var7 >= 0) {
            var9 = 0;

            for(var11 = 0; var11 < 4; ++var11) {
               var9 <<= 8;
               int var12 = var3[var10++];
               if (var12 < 0) {
                  var12 += 256;
               }

               var9 |= var12;
            }

            this.m_ints[var7] = var9;
            --var7;
         }

      }
   }

   public boolean isZero() {
      return this.m_ints.length == 0 || this.m_ints[0] == 0 && this.getUsedLength() == 0;
   }

   public int getUsedLength() {
      int var1 = this.m_ints.length;
      if (var1 < 1) {
         return 0;
      } else if (this.m_ints[0] != 0) {
         do {
            --var1;
         } while(this.m_ints[var1] == 0);

         return var1 + 1;
      } else {
         do {
            --var1;
            if (this.m_ints[var1] != 0) {
               return var1 + 1;
            }
         } while(var1 > 0);

         return 0;
      }
   }

   public int bitLength() {
      int var1 = this.getUsedLength();
      if (var1 == 0) {
         return 0;
      } else {
         int var2 = var1 - 1;
         int var3 = this.m_ints[var2];
         int var4 = (var2 << 5) + 1;
         if ((var3 & -65536) != 0) {
            if ((var3 & -16777216) != 0) {
               var4 += 24;
               var3 >>>= 24;
            } else {
               var4 += 16;
               var3 >>>= 16;
            }
         } else if (var3 > 255) {
            var4 += 8;
            var3 >>>= 8;
         }

         while(var3 != 1) {
            ++var4;
            var3 >>>= 1;
         }

         return var4;
      }
   }

   private int[] resizedInts(int var1) {
      int[] var2 = new int[var1];
      int var3 = this.m_ints.length;
      int var4 = var3 < var1 ? var3 : var1;
      System.arraycopy(this.m_ints, 0, var2, 0, var4);
      return var2;
   }

   public BigInteger toBigInteger() {
      int var1 = this.getUsedLength();
      if (var1 == 0) {
         return ECConstants.ZERO;
      } else {
         int var2 = this.m_ints[var1 - 1];
         byte[] var3 = new byte[4];
         int var4 = 0;
         boolean var5 = false;

         int var6;
         for(var6 = 3; var6 >= 0; --var6) {
            byte var7 = (byte)(var2 >>> 8 * var6);
            if (var5 || var7 != 0) {
               var5 = true;
               var3[var4++] = var7;
            }
         }

         var6 = 4 * (var1 - 1) + var4;
         byte[] var10 = new byte[var6];

         int var8;
         for(var8 = 0; var8 < var4; ++var8) {
            var10[var8] = var3[var8];
         }

         for(var8 = var1 - 2; var8 >= 0; --var8) {
            for(int var9 = 3; var9 >= 0; --var9) {
               var10[var4++] = (byte)(this.m_ints[var8] >>> 8 * var9);
            }
         }

         return new BigInteger(1, var10);
      }
   }

   public void shiftLeft() {
      int var1 = this.getUsedLength();
      if (var1 != 0) {
         if (this.m_ints[var1 - 1] < 0) {
            ++var1;
            if (var1 > this.m_ints.length) {
               this.m_ints = this.resizedInts(this.m_ints.length + 1);
            }
         }

         boolean var2 = false;

         for(int var3 = 0; var3 < var1; ++var3) {
            boolean var4 = this.m_ints[var3] < 0;
            this.m_ints[var3] <<= 1;
            if (var2) {
               this.m_ints[var3] |= 1;
            }

            var2 = var4;
         }

      }
   }

   public IntArray shiftLeft(int var1) {
      int var2 = this.getUsedLength();
      if (var2 == 0) {
         return this;
      } else if (var1 == 0) {
         return this;
      } else if (var1 > 31) {
         throw new IllegalArgumentException("shiftLeft() for max 31 bits , " + var1 + "bit shift is not possible");
      } else {
         int[] var3 = new int[var2 + 1];
         int var4 = 32 - var1;
         var3[0] = this.m_ints[0] << var1;

         for(int var5 = 1; var5 < var2; ++var5) {
            var3[var5] = this.m_ints[var5] << var1 | this.m_ints[var5 - 1] >>> var4;
         }

         var3[var2] = this.m_ints[var2 - 1] >>> var4;
         return new IntArray(var3);
      }
   }

   public void addShifted(IntArray var1, int var2) {
      int var3 = var1.getUsedLength();
      int var4 = var3 + var2;
      if (var4 > this.m_ints.length) {
         this.m_ints = this.resizedInts(var4);
      }

      for(int var5 = 0; var5 < var3; ++var5) {
         this.m_ints[var5 + var2] ^= var1.m_ints[var5];
      }

   }

   public int getLength() {
      return this.m_ints.length;
   }

   public boolean testBit(int var1) {
      int var2 = var1 >> 5;
      int var3 = var1 & 31;
      int var4 = 1 << var3;
      return (this.m_ints[var2] & var4) != 0;
   }

   public void flipBit(int var1) {
      int var2 = var1 >> 5;
      int var3 = var1 & 31;
      int var4 = 1 << var3;
      this.m_ints[var2] ^= var4;
   }

   public void setBit(int var1) {
      int var2 = var1 >> 5;
      int var3 = var1 & 31;
      int var4 = 1 << var3;
      this.m_ints[var2] |= var4;
   }

   public IntArray multiply(IntArray var1, int var2) {
      int var3 = var2 + 31 >> 5;
      if (this.m_ints.length < var3) {
         this.m_ints = this.resizedInts(var3);
      }

      IntArray var4 = new IntArray(var1.resizedInts(var1.getLength() + 1));
      IntArray var5 = new IntArray(var2 + var2 + 31 >> 5);
      int var6 = 1;

      for(int var7 = 0; var7 < 32; ++var7) {
         for(int var8 = 0; var8 < var3; ++var8) {
            if ((this.m_ints[var8] & var6) != 0) {
               var5.addShifted(var4, var8);
            }
         }

         var6 <<= 1;
         var4.shiftLeft();
      }

      return var5;
   }

   public void reduce(int var1, int[] var2) {
      for(int var3 = var1 + var1 - 2; var3 >= var1; --var3) {
         if (this.testBit(var3)) {
            int var4 = var3 - var1;
            this.flipBit(var4);
            this.flipBit(var3);
            int var5 = var2.length;

            while(true) {
               --var5;
               if (var5 < 0) {
                  break;
               }

               this.flipBit(var2[var5] + var4);
            }
         }
      }

      this.m_ints = this.resizedInts(var1 + 31 >> 5);
   }

   public IntArray square(int var1) {
      int[] var2 = new int[]{0, 1, 4, 5, 16, 17, 20, 21, 64, 65, 68, 69, 80, 81, 84, 85};
      int var3 = var1 + 31 >> 5;
      if (this.m_ints.length < var3) {
         this.m_ints = this.resizedInts(var3);
      }

      IntArray var4 = new IntArray(var3 + var3);

      for(int var5 = 0; var5 < var3; ++var5) {
         int var6 = 0;

         int var7;
         int var8;
         int var9;
         for(var7 = 0; var7 < 4; ++var7) {
            var6 >>>= 8;
            var8 = this.m_ints[var5] >>> var7 * 4 & 15;
            var9 = var2[var8] << 24;
            var6 |= var9;
         }

         var4.m_ints[var5 + var5] = var6;
         var6 = 0;
         var7 = this.m_ints[var5] >>> 16;

         for(var8 = 0; var8 < 4; ++var8) {
            var6 >>>= 8;
            var9 = var7 >>> var8 * 4 & 15;
            int var10 = var2[var9] << 24;
            var6 |= var10;
         }

         var4.m_ints[var5 + var5 + 1] = var6;
      }

      return var4;
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof IntArray)) {
         return false;
      } else {
         IntArray var2 = (IntArray)var1;
         int var3 = this.getUsedLength();
         if (var2.getUsedLength() != var3) {
            return false;
         } else {
            for(int var4 = 0; var4 < var3; ++var4) {
               if (this.m_ints[var4] != var2.m_ints[var4]) {
                  return false;
               }
            }

            return true;
         }
      }
   }

   public int hashCode() {
      int var1 = this.getUsedLength();
      int var2 = 1;

      for(int var3 = 0; var3 < var1; ++var3) {
         var2 = var2 * 31 + this.m_ints[var3];
      }

      return var2;
   }

   public Object clone() {
      return new IntArray(Arrays.clone(this.m_ints));
   }

   public String toString() {
      int var1 = this.getUsedLength();
      if (var1 == 0) {
         return "0";
      } else {
         StringBuffer var2 = new StringBuffer(Integer.toBinaryString(this.m_ints[var1 - 1]));

         for(int var3 = var1 - 2; var3 >= 0; --var3) {
            String var4 = Integer.toBinaryString(this.m_ints[var3]);

            for(int var5 = var4.length(); var5 < 8; ++var5) {
               var4 = "0" + var4;
            }

            var2.append(var4);
         }

         return var2.toString();
      }
   }
}
