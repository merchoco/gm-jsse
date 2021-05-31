package org.bc.crypto.signers;

import java.nio.ByteBuffer;
import org.bc.crypto.Digest;

public class NTRUSignerPrng {
   private int counter = 0;
   private byte[] seed;
   private Digest hashAlg;

   NTRUSignerPrng(byte[] var1, Digest var2) {
      this.seed = var1;
      this.hashAlg = var2;
   }

   byte[] nextBytes(int var1) {
      ByteBuffer var2;
      for(var2 = ByteBuffer.allocate(var1); var2.hasRemaining(); ++this.counter) {
         ByteBuffer var3 = ByteBuffer.allocate(this.seed.length + 4);
         var3.put(this.seed);
         var3.putInt(this.counter);
         byte[] var4 = var3.array();
         byte[] var5 = new byte[this.hashAlg.getDigestSize()];
         this.hashAlg.update(var4, 0, var4.length);
         this.hashAlg.doFinal(var5, 0);
         if (var2.remaining() < var5.length) {
            var2.put(var5, 0, var2.remaining());
         } else {
            var2.put(var5);
         }
      }

      return var2.array();
   }
}
