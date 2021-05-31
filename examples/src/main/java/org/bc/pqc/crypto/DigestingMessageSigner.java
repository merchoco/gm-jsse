package org.bc.pqc.crypto;

import org.bc.crypto.CipherParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.Signer;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;

public class DigestingMessageSigner implements Signer {
   private final Digest messDigest;
   private final MessageSigner messSigner;
   private boolean forSigning;

   public DigestingMessageSigner(MessageSigner var1, Digest var2) {
      this.messSigner = var1;
      this.messDigest = var2;
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
         throw new IllegalArgumentException("Signing Requires Private Key.");
      } else if (!var1 && var3.isPrivate()) {
         throw new IllegalArgumentException("Verification Requires Public Key.");
      } else {
         this.reset();
         this.messSigner.init(var1, var2);
      }
   }

   public byte[] generateSignature() {
      if (!this.forSigning) {
         throw new IllegalStateException("RainbowDigestSigner not initialised for signature generation.");
      } else {
         byte[] var1 = new byte[this.messDigest.getDigestSize()];
         this.messDigest.doFinal(var1, 0);
         return this.messSigner.generateSignature(var1);
      }
   }

   public boolean verify(byte[] var1) {
      if (this.forSigning) {
         throw new IllegalStateException("RainbowDigestSigner not initialised for verification");
      } else {
         byte[] var2 = new byte[this.messDigest.getDigestSize()];
         this.messDigest.doFinal(var2, 0);
         return this.messSigner.verifySignature(var2, var1);
      }
   }

   public void update(byte var1) {
      this.messDigest.update(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.messDigest.update(var1, var2, var3);
   }

   public void reset() {
      this.messDigest.reset();
   }

   public boolean verifySignature(byte[] var1) {
      return this.verify(var1);
   }
}
