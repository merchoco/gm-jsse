package cn.gmssl.security.util;

import java.math.BigInteger;

public final class BigInt {
   private byte[] places;
   private static final String digits = "0123456789abcdef";

   public BigInt(byte[] var1) {
      this.places = (byte[])var1.clone();
   }

   public BigInt(BigInteger var1) {
      byte[] var2 = var1.toByteArray();
      if ((var2[0] & 128) != 0) {
         throw new IllegalArgumentException("negative BigInteger");
      } else {
         if (var2[0] != 0) {
            this.places = var2;
         } else {
            this.places = new byte[var2.length - 1];

            for(int var3 = 1; var3 < var2.length; ++var3) {
               this.places[var3 - 1] = var2[var3];
            }
         }

      }
   }

   public BigInt(int var1) {
      if (var1 < 256) {
         this.places = new byte[1];
         this.places[0] = (byte)var1;
      } else if (var1 < 65536) {
         this.places = new byte[2];
         this.places[0] = (byte)(var1 >> 8);
         this.places[1] = (byte)var1;
      } else if (var1 < 16777216) {
         this.places = new byte[3];
         this.places[0] = (byte)(var1 >> 16);
         this.places[1] = (byte)(var1 >> 8);
         this.places[2] = (byte)var1;
      } else {
         this.places = new byte[4];
         this.places[0] = (byte)(var1 >> 24);
         this.places[1] = (byte)(var1 >> 16);
         this.places[2] = (byte)(var1 >> 8);
         this.places[3] = (byte)var1;
      }

   }

   public int toInt() {
      if (this.places.length > 4) {
         throw new NumberFormatException("BigInt.toLong, too big");
      } else {
         int var1 = 0;

         for(int var2 = 0; var2 < this.places.length; ++var2) {
            var1 = (var1 << 8) + (this.places[var2] & 255);
         }

         return var1;
      }
   }

   public String toString() {
      return this.hexify();
   }

   public BigInteger toBigInteger() {
      return new BigInteger(1, this.places);
   }

   public byte[] toByteArray() {
      return (byte[])this.places.clone();
   }

   private String hexify() {
      if (this.places.length == 0) {
         return "  0  ";
      } else {
         StringBuffer var1 = new StringBuffer(this.places.length * 2);
         var1.append("    ");

         for(int var2 = 0; var2 < this.places.length; ++var2) {
            var1.append("0123456789abcdef".charAt(this.places[var2] >> 4 & 15));
            var1.append("0123456789abcdef".charAt(this.places[var2] & 15));
            if ((var2 + 1) % 32 == 0) {
               if (var2 + 1 != this.places.length) {
                  var1.append("\n    ");
               }
            } else if ((var2 + 1) % 4 == 0) {
               var1.append(' ');
            }
         }

         return var1.toString();
      }
   }

   public boolean equals(Object var1) {
      return var1 instanceof BigInt ? this.equals((BigInt)var1) : false;
   }

   public boolean equals(BigInt var1) {
      if (this == var1) {
         return true;
      } else {
         byte[] var2 = var1.toByteArray();
         if (this.places.length != var2.length) {
            return false;
         } else {
            for(int var3 = 0; var3 < this.places.length; ++var3) {
               if (this.places[var3] != var2[var3]) {
                  return false;
               }
            }

            return true;
         }
      }
   }

   public int hashCode() {
      return this.hexify().hashCode();
   }
}
