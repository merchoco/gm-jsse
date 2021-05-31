package org.bc.crypto.engines;

import org.bc.crypto.CipherParameters;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.MaxBytesExceededException;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;
import org.bc.crypto.util.Pack;
import org.bc.util.Strings;

public class Salsa20Engine implements StreamCipher {
   private static final int STATE_SIZE = 16;
   private static final byte[] sigma = Strings.toByteArray("expand 32-byte k");
   private static final byte[] tau = Strings.toByteArray("expand 16-byte k");
   private int index = 0;
   private int[] engineState = new int[16];
   private int[] x = new int[16];
   private byte[] keyStream = new byte[64];
   private byte[] workingKey = null;
   private byte[] workingIV = null;
   private boolean initialised = false;
   private int cW0;
   private int cW1;
   private int cW2;

   public void init(boolean var1, CipherParameters var2) {
      if (!(var2 instanceof ParametersWithIV)) {
         throw new IllegalArgumentException("Salsa20 Init parameters must include an IV");
      } else {
         ParametersWithIV var3 = (ParametersWithIV)var2;
         byte[] var4 = var3.getIV();
         if (var4 != null && var4.length == 8) {
            if (!(var3.getParameters() instanceof KeyParameter)) {
               throw new IllegalArgumentException("Salsa20 Init parameters must include a key");
            } else {
               KeyParameter var5 = (KeyParameter)var3.getParameters();
               this.workingKey = var5.getKey();
               this.workingIV = var4;
               this.setKey(this.workingKey, this.workingIV);
            }
         } else {
            throw new IllegalArgumentException("Salsa20 requires exactly 8 bytes of IV");
         }
      }
   }

   public String getAlgorithmName() {
      return "Salsa20";
   }

   public byte returnByte(byte var1) {
      if (this.limitExceeded()) {
         throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
      } else {
         if (this.index == 0) {
            this.generateKeyStream(this.keyStream);
            if (++this.engineState[8] == 0) {
               ++this.engineState[9];
            }
         }

         byte var2 = (byte)(this.keyStream[this.index] ^ var1);
         this.index = this.index + 1 & 63;
         return var2;
      }
   }

   public void processBytes(byte[] var1, int var2, int var3, byte[] var4, int var5) {
      if (!this.initialised) {
         throw new IllegalStateException(this.getAlgorithmName() + " not initialised");
      } else if (var2 + var3 > var1.length) {
         throw new DataLengthException("input buffer too short");
      } else if (var5 + var3 > var4.length) {
         throw new DataLengthException("output buffer too short");
      } else if (this.limitExceeded(var3)) {
         throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
      } else {
         for(int var6 = 0; var6 < var3; ++var6) {
            if (this.index == 0) {
               this.generateKeyStream(this.keyStream);
               if (++this.engineState[8] == 0) {
                  ++this.engineState[9];
               }
            }

            var4[var6 + var5] = (byte)(this.keyStream[this.index] ^ var1[var6 + var2]);
            this.index = this.index + 1 & 63;
         }

      }
   }

   public void reset() {
      this.setKey(this.workingKey, this.workingIV);
   }

   private void setKey(byte[] var1, byte[] var2) {
      this.workingKey = var1;
      this.workingIV = var2;
      this.index = 0;
      this.resetCounter();
      byte var3 = 0;
      this.engineState[1] = Pack.littleEndianToInt(this.workingKey, 0);
      this.engineState[2] = Pack.littleEndianToInt(this.workingKey, 4);
      this.engineState[3] = Pack.littleEndianToInt(this.workingKey, 8);
      this.engineState[4] = Pack.littleEndianToInt(this.workingKey, 12);
      byte[] var4;
      if (this.workingKey.length == 32) {
         var4 = sigma;
         var3 = 16;
      } else {
         var4 = tau;
      }

      this.engineState[11] = Pack.littleEndianToInt(this.workingKey, var3);
      this.engineState[12] = Pack.littleEndianToInt(this.workingKey, var3 + 4);
      this.engineState[13] = Pack.littleEndianToInt(this.workingKey, var3 + 8);
      this.engineState[14] = Pack.littleEndianToInt(this.workingKey, var3 + 12);
      this.engineState[0] = Pack.littleEndianToInt(var4, 0);
      this.engineState[5] = Pack.littleEndianToInt(var4, 4);
      this.engineState[10] = Pack.littleEndianToInt(var4, 8);
      this.engineState[15] = Pack.littleEndianToInt(var4, 12);
      this.engineState[6] = Pack.littleEndianToInt(this.workingIV, 0);
      this.engineState[7] = Pack.littleEndianToInt(this.workingIV, 4);
      this.engineState[8] = this.engineState[9] = 0;
      this.initialised = true;
   }

   private void generateKeyStream(byte[] var1) {
      salsaCore(20, this.engineState, this.x);
      Pack.intToLittleEndian(this.x, var1, 0);
   }

   public static void salsaCore(int var0, int[] var1, int[] var2) {
      System.arraycopy(var1, 0, var2, 0, var1.length);

      int var3;
      for(var3 = var0; var3 > 0; var3 -= 2) {
         var2[4] ^= rotl(var2[0] + var2[12], 7);
         var2[8] ^= rotl(var2[4] + var2[0], 9);
         var2[12] ^= rotl(var2[8] + var2[4], 13);
         var2[0] ^= rotl(var2[12] + var2[8], 18);
         var2[9] ^= rotl(var2[5] + var2[1], 7);
         var2[13] ^= rotl(var2[9] + var2[5], 9);
         var2[1] ^= rotl(var2[13] + var2[9], 13);
         var2[5] ^= rotl(var2[1] + var2[13], 18);
         var2[14] ^= rotl(var2[10] + var2[6], 7);
         var2[2] ^= rotl(var2[14] + var2[10], 9);
         var2[6] ^= rotl(var2[2] + var2[14], 13);
         var2[10] ^= rotl(var2[6] + var2[2], 18);
         var2[3] ^= rotl(var2[15] + var2[11], 7);
         var2[7] ^= rotl(var2[3] + var2[15], 9);
         var2[11] ^= rotl(var2[7] + var2[3], 13);
         var2[15] ^= rotl(var2[11] + var2[7], 18);
         var2[1] ^= rotl(var2[0] + var2[3], 7);
         var2[2] ^= rotl(var2[1] + var2[0], 9);
         var2[3] ^= rotl(var2[2] + var2[1], 13);
         var2[0] ^= rotl(var2[3] + var2[2], 18);
         var2[6] ^= rotl(var2[5] + var2[4], 7);
         var2[7] ^= rotl(var2[6] + var2[5], 9);
         var2[4] ^= rotl(var2[7] + var2[6], 13);
         var2[5] ^= rotl(var2[4] + var2[7], 18);
         var2[11] ^= rotl(var2[10] + var2[9], 7);
         var2[8] ^= rotl(var2[11] + var2[10], 9);
         var2[9] ^= rotl(var2[8] + var2[11], 13);
         var2[10] ^= rotl(var2[9] + var2[8], 18);
         var2[12] ^= rotl(var2[15] + var2[14], 7);
         var2[13] ^= rotl(var2[12] + var2[15], 9);
         var2[14] ^= rotl(var2[13] + var2[12], 13);
         var2[15] ^= rotl(var2[14] + var2[13], 18);
      }

      for(var3 = 0; var3 < 16; ++var3) {
         var2[var3] += var1[var3];
      }

   }

   private static int rotl(int var0, int var1) {
      return var0 << var1 | var0 >>> -var1;
   }

   private void resetCounter() {
      this.cW0 = 0;
      this.cW1 = 0;
      this.cW2 = 0;
   }

   private boolean limitExceeded() {
      if (++this.cW0 == 0 && ++this.cW1 == 0) {
         return (++this.cW2 & 32) != 0;
      } else {
         return false;
      }
   }

   private boolean limitExceeded(int var1) {
      this.cW0 += var1;
      if (this.cW0 < var1 && this.cW0 >= 0 && ++this.cW1 == 0) {
         return (++this.cW2 & 32) != 0;
      } else {
         return false;
      }
   }
}
