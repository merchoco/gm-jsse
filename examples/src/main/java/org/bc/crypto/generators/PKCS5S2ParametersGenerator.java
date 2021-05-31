package org.bc.crypto.generators;

import org.bc.crypto.CipherParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.Mac;
import org.bc.crypto.PBEParametersGenerator;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.macs.HMac;
import org.bc.crypto.params.KeyParameter;
import org.bc.crypto.params.ParametersWithIV;

public class PKCS5S2ParametersGenerator extends PBEParametersGenerator {
   private Mac hMac;

   public PKCS5S2ParametersGenerator() {
      this(new SHA1Digest());
   }

   public PKCS5S2ParametersGenerator(Digest var1) {
      this.hMac = new HMac(var1);
   }

   private void F(byte[] var1, byte[] var2, int var3, byte[] var4, byte[] var5, int var6) {
      byte[] var7 = new byte[this.hMac.getMacSize()];
      KeyParameter var8 = new KeyParameter(var1);
      this.hMac.init(var8);
      if (var2 != null) {
         this.hMac.update(var2, 0, var2.length);
      }

      this.hMac.update(var4, 0, var4.length);
      this.hMac.doFinal(var7, 0);
      System.arraycopy(var7, 0, var5, var6, var7.length);
      if (var3 == 0) {
         throw new IllegalArgumentException("iteration count must be at least 1.");
      } else {
         for(int var9 = 1; var9 < var3; ++var9) {
            this.hMac.init(var8);
            this.hMac.update(var7, 0, var7.length);
            this.hMac.doFinal(var7, 0);

            for(int var10 = 0; var10 != var7.length; ++var10) {
               var5[var6 + var10] ^= var7[var10];
            }
         }

      }
   }

   private void intToOctet(byte[] var1, int var2) {
      var1[0] = (byte)(var2 >>> 24);
      var1[1] = (byte)(var2 >>> 16);
      var1[2] = (byte)(var2 >>> 8);
      var1[3] = (byte)var2;
   }

   private byte[] generateDerivedKey(int var1) {
      int var2 = this.hMac.getMacSize();
      int var3 = (var1 + var2 - 1) / var2;
      byte[] var4 = new byte[4];
      byte[] var5 = new byte[var3 * var2];

      for(int var6 = 1; var6 <= var3; ++var6) {
         this.intToOctet(var4, var6);
         this.F(this.password, this.salt, this.iterationCount, var4, var5, (var6 - 1) * var2);
      }

      return var5;
   }

   public CipherParameters generateDerivedParameters(int var1) {
      var1 /= 8;
      byte[] var2 = this.generateDerivedKey(var1);
      return new KeyParameter(var2, 0, var1);
   }

   public CipherParameters generateDerivedParameters(int var1, int var2) {
      var1 /= 8;
      var2 /= 8;
      byte[] var3 = this.generateDerivedKey(var1 + var2);
      return new ParametersWithIV(new KeyParameter(var3, 0, var1), var3, var1, var2);
   }

   public CipherParameters generateDerivedMacParameters(int var1) {
      return this.generateDerivedParameters(var1);
   }
}
