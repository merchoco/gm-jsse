package org.bc.crypto.engines;

import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.params.KeyParameter;

public class ISAACEngine implements StreamCipher {
   private final int sizeL = 8;
   private final int stateArraySize = 256;
   private int[] engineState = null;
   private int[] results = null;
   private int a = 0;
   private int b = 0;
   private int c = 0;
   private int index = 0;
   private byte[] keyStream = new byte[1024];
   private byte[] workingKey = null;
   private boolean initialised = false;

   public void init(boolean var1, CipherParameters var2) {
      if (!(var2 instanceof KeyParameter)) {
         throw new IllegalArgumentException("invalid parameter passed to ISAAC init - " + var2.getClass().getName());
      } else {
         KeyParameter var3 = (KeyParameter)var2;
         this.setKey(var3.getKey());
      }
   }

   public byte returnByte(byte var1) {
      if (this.index == 0) {
         this.isaac();
         this.keyStream = this.intToByteLittle(this.results);
      }

      byte var2 = (byte)(this.keyStream[this.index] ^ var1);
      this.index = this.index + 1 & 1023;
      return var2;
   }

   public void processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      if (!this.initialised) {
         throw new IllegalStateException(this.getAlgorithmName() + " not initialised");
      } else if (var2 + var3 > var1.length) {
         throw new DataLengthException("input buffer too short");
      } else if (var5 + var3 > var4.length) {
         throw new DataLengthException("output buffer too short");
      } else {
         for(int var6 = 0; var6 < var3; ++var6) {
            if (this.index == 0) {
               this.isaac();
               this.keyStream = this.intToByteLittle(this.results);
            }

            var4[var6 + var5] = (byte)(this.keyStream[this.index] ^ var1[var6 + var2]);
            this.index = this.index + 1 & 1023;
         }

      }
   }

   public String getAlgorithmName() {
      return "ISAAC";
   }

   public void reset() {
      this.setKey(this.workingKey);
   }

   private void setKey(byte[] var1) {
      this.workingKey = var1;
      if (this.engineState == null) {
         this.engineState = new int[256];
      }

      if (this.results == null) {
         this.results = new int[256];
      }

      int var2;
      for(var2 = 0; var2 < 256; ++var2) {
         this.engineState[var2] = this.results[var2] = 0;
      }

      this.a = this.b = this.c = 0;
      this.index = 0;
      byte[] var5 = new byte[var1.length + (var1.length & 3)];
      System.arraycopy(var1, 0, var5, 0, var1.length);

      for(var2 = 0; var2 < var5.length; var2 += 4) {
         this.results[var2 >> 2] = this.byteToIntLittle(var5, var2);
      }

      int[] var6 = new int[8];

      for(var2 = 0; var2 < 8; ++var2) {
         var6[var2] = -1640531527;
      }

      for(var2 = 0; var2 < 4; ++var2) {
         this.mix(var6);
      }

      for(var2 = 0; var2 < 2; ++var2) {
         for(int var3 = 0; var3 < 256; var3 += 8) {
            int var4;
            for(var4 = 0; var4 < 8; ++var4) {
               var6[var4] += var2 < 1 ? this.results[var3 + var4] : this.engineState[var3 + var4];
            }

            this.mix(var6);

            for(var4 = 0; var4 < 8; ++var4) {
               this.engineState[var3 + var4] = var6[var4];
            }
         }
      }

      this.isaac();
      this.initialised = true;
   }

   private void isaac() {
      this.b += ++this.c;

      for(int var1 = 0; var1 < 256; ++var1) {
         int var2 = this.engineState[var1];
         switch(var1 & 3) {
         case 0:
            this.a ^= this.a << 13;
            break;
         case 1:
            this.a ^= this.a >>> 6;
            break;
         case 2:
            this.a ^= this.a << 2;
            break;
         case 3:
            this.a ^= this.a >>> 16;
         }

         this.a += this.engineState[var1 + 128 & 255];
         int var3;
         this.engineState[var1] = var3 = this.engineState[var2 >>> 2 & 255] + this.a + this.b;
         this.results[var1] = this.b = this.engineState[var3 >>> 10 & 255] + var2;
      }

   }

   private void mix(int[] var1) {
      var1[0] ^= var1[1] << 11;
      var1[3] += var1[0];
      var1[1] += var1[2];
      var1[1] ^= var1[2] >>> 2;
      var1[4] += var1[1];
      var1[2] += var1[3];
      var1[2] ^= var1[3] << 8;
      var1[5] += var1[2];
      var1[3] += var1[4];
      var1[3] ^= var1[4] >>> 16;
      var1[6] += var1[3];
      var1[4] += var1[5];
      var1[4] ^= var1[5] << 10;
      var1[7] += var1[4];
      var1[5] += var1[6];
      var1[5] ^= var1[6] >>> 4;
      var1[0] += var1[5];
      var1[6] += var1[7];
      var1[6] ^= var1[7] << 8;
      var1[1] += var1[6];
      var1[7] += var1[0];
      var1[7] ^= var1[0] >>> 9;
      var1[2] += var1[7];
      var1[0] += var1[1];
   }

   private int byteToIntLittle(byte[] var1, int var2) {
      return var1[var2++] & 255 | (var1[var2++] & 255) << 8 | (var1[var2++] & 255) << 16 | var1[var2++] << 24;
   }

   private byte[] intToByteLittle(int var1) {
      byte[] var2 = new byte[]{(byte)(var1 >>> 24), (byte)(var1 >>> 16), (byte)(var1 >>> 8), (byte)var1};
      return var2;
   }

   private byte[] intToByteLittle(int[] var1) {
      byte[] var2 = new byte[4 * var1.length];
      int var3 = 0;

      for(int var4 = 0; var3 < var1.length; var4 += 4) {
         System.arraycopy(this.intToByteLittle(var1[var3]), 0, var2, var4, 4);
         ++var3;
      }

      return var2;
   }
}
