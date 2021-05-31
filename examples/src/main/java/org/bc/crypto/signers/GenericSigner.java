package org.bc.crypto.signers;

import org.bc.crypto.AsymmetricBlockCipher;
import org.bc.crypto.CipherParameters;
import org.bc.crypto.CryptoException;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.Digest;
import org.bc.crypto.Signer;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.util.Arrays;

public class GenericSigner implements Signer {
   private final AsymmetricBlockCipher engine;
   private final Digest digest;
   private boolean forSigning;

   public GenericSigner(AsymmetricBlockCipher var1, Digest var2) {
      this.engine = var1;
      this.digest = var2;
   }

   public void init(boolean var1, CipherParameters var2) {
      this.forSigning = var1;
      AsymmetricKeyParameter var3;
      if (var2 instanceof ParametersWithRandom) {
         var3 = (AsymmetricKeyParameter)((ParametersWithRandom)var2).getParameters();
      } else {
         var3 = (AsymmetricKeyParameter)var2;
      }

      if (var1 && !var3.isPrivate()) {
         throw new IllegalArgumentException("signing requires private key");
      } else if (!var1 && var3.isPrivate()) {
         throw new IllegalArgumentException("verification requires public key");
      } else {
         this.reset();
         this.engine.init(var1, var2);
      }
   }

   public void update(byte var1) {
      this.digest.update(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.digest.update(var1, var2, var3);
   }

   public byte[] generateSignature() throws CryptoException, DataLengthException {
      if (!this.forSigning) {
         throw new IllegalStateException("GenericSigner not initialised for signature generation.");
      } else {
         byte[] var1 = new byte[this.digest.getDigestSize()];
         this.digest.doFinal(var1, 0);
         return this.engine.processBlock(var1, 0, var1.length);
      }
   }

   public boolean verifySignature(byte[] var1) {
      if (this.forSigning) {
         throw new IllegalStateException("GenericSigner not initialised for verification");
      } else {
         byte[] var2 = new byte[this.digest.getDigestSize()];
         this.digest.doFinal(var2, 0);

         try {
            byte[] var3 = this.engine.processBlock(var1, 0, var1.length);
            return Arrays.constantTimeAreEqual(var3, var2);
         } catch (Exception var4) {
            return false;
         }
      }
   }

   public void reset() {
      this.digest.reset();
   }
}
