package org.bc.crypto.macs;

import java.util.Hashtable;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.ExtendedDigest;
import org.bc.crypto.Mac;
import org.bc.crypto.params.KeyParameter;
import org.bc.util.Integers;

public class HMac implements Mac {
   private static final byte IPAD = 54;
   private static final byte OPAD = 92;
   private Digest digest;
   private int digestSize;
   private int blockLength;
   private byte[] inputPad;
   private byte[] outputPad;
   private static Hashtable blockLengths = new Hashtable();

   static {
      blockLengths.put("GOST3411", Integers.valueOf(32));
      blockLengths.put("MD2", Integers.valueOf(16));
      blockLengths.put("MD4", Integers.valueOf(64));
      blockLengths.put("MD5", Integers.valueOf(64));
      blockLengths.put("RIPEMD128", Integers.valueOf(64));
      blockLengths.put("RIPEMD160", Integers.valueOf(64));
      blockLengths.put("SHA-1", Integers.valueOf(64));
      blockLengths.put("SHA-224", Integers.valueOf(64));
      blockLengths.put("SHA-256", Integers.valueOf(64));
      blockLengths.put("SHA-384", Integers.valueOf(128));
      blockLengths.put("SHA-512", Integers.valueOf(128));
      blockLengths.put("Tiger", Integers.valueOf(64));
      blockLengths.put("Whirlpool", Integers.valueOf(64));
   }

   private static int getByteLength(Digest var0) {
      if (var0 instanceof ExtendedDigest) {
         return ((ExtendedDigest)var0).getByteLength();
      } else {
         Integer var1 = (Integer)blockLengths.get(var0.getAlgorithmName());
         if (var1 == null) {
            throw new IllegalArgumentException("unknown digest passed: " + var0.getAlgorithmName());
         } else {
            return var1;
         }
      }
   }

   public HMac(Digest var1) {
      this(var1, getByteLength(var1));
   }

   private HMac(Digest var1, int var2) {
      this.digest = var1;
      this.digestSize = var1.getDigestSize();
      this.blockLength = var2;
      this.inputPad = new byte[this.blockLength];
      this.outputPad = new byte[this.blockLength];
   }

   public String getAlgorithmName() {
      return this.digest.getAlgorithmName() + "/HMAC";
   }

   public Digest getUnderlyingDigest() {
      return this.digest;
   }

   public void init(CipherParameters var1) {
      this.digest.reset();
      byte[] var2 = ((KeyParameter)var1).getKey();
      int var3;
      if (var2.length > this.blockLength) {
         this.digest.update(var2, 0, var2.length);
         this.digest.doFinal(this.inputPad, 0);

         for(var3 = this.digestSize; var3 < this.inputPad.length; ++var3) {
            this.inputPad[var3] = 0;
         }
      } else {
         System.arraycopy(var2, 0, this.inputPad, 0, var2.length);

         for(var3 = var2.length; var3 < this.inputPad.length; ++var3) {
            this.inputPad[var3] = 0;
         }
      }

      this.outputPad = new byte[this.inputPad.length];
      System.arraycopy(this.inputPad, 0, this.outputPad, 0, this.inputPad.length);

      for(var3 = 0; var3 < this.inputPad.length; ++var3) {
         this.inputPad[var3] = (byte)(this.inputPad[var3] ^ 54);
      }

      for(var3 = 0; var3 < this.outputPad.length; ++var3) {
         this.outputPad[var3] = (byte)(this.outputPad[var3] ^ 92);
      }

      this.digest.update(this.inputPad, 0, this.inputPad.length);
   }

   public int getMacSize() {
      return this.digestSize;
   }

   public void update(byte var1) {
      this.digest.update(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.digest.update(var1, var2, var3);
   }

   public int doFinal(byte[] var1, int var2) {
      byte[] var3 = new byte[this.digestSize];
      this.digest.doFinal(var3, 0);
      this.digest.update(this.outputPad, 0, this.outputPad.length);
      this.digest.update(var3, 0, var3.length);
      int var4 = this.digest.doFinal(var1, var2);
      this.reset();
      return var4;
   }

   public void reset() {
      this.digest.reset();
      this.digest.update(this.inputPad, 0, this.inputPad.length);
   }
}
