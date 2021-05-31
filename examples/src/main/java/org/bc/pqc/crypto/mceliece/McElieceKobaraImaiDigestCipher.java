package org.bc.pqc.crypto.mceliece;

import org.bc.crypto.CipherParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.pqc.crypto.MessageEncryptor;

public class McElieceKobaraImaiDigestCipher {
   private final Digest messDigest;
   private final MessageEncryptor mcElieceCCA2Cipher;
   private boolean forEncrypting;

   public McElieceKobaraImaiDigestCipher(MessageEncryptor var1, Digest var2) {
      this.mcElieceCCA2Cipher = var1;
      this.messDigest = var2;
   }

   public void init(boolean var1, CipherParameters var2) {
      this.forEncrypting = var1;
      AsymmetricKeyParameter var3;
      if (var2 instanceof ParametersWithRandom) {
         var3 = (AsymmetricKeyParameter)((ParametersWithRandom)var2).getParameters();
      } else {
         var3 = (AsymmetricKeyParameter)var2;
      }

      if (var1 && var3.isPrivate()) {
         throw new IllegalArgumentException("Encrypting Requires Public Key.");
      } else if (!var1 && !var3.isPrivate()) {
         throw new IllegalArgumentException("Decrypting Requires Private Key.");
      } else {
         this.reset();
         this.mcElieceCCA2Cipher.init(var1, var2);
      }
   }

   public byte[] messageEncrypt() {
      if (!this.forEncrypting) {
         throw new IllegalStateException("McElieceKobaraImaiDigestCipher not initialised for encrypting.");
      } else {
         byte[] var1 = new byte[this.messDigest.getDigestSize()];
         this.messDigest.doFinal(var1, 0);
         byte[] var2 = null;

         try {
            var2 = this.mcElieceCCA2Cipher.messageEncrypt(var1);
         } catch (Exception var4) {
            var4.printStackTrace();
         }

         return var2;
      }
   }

   public byte[] messageDecrypt(byte[] var1) {
      byte[] var2 = null;
      if (this.forEncrypting) {
         throw new IllegalStateException("McElieceKobaraImaiDigestCipher not initialised for decrypting.");
      } else {
         try {
            var2 = this.mcElieceCCA2Cipher.messageDecrypt(var1);
         } catch (Exception var4) {
            var4.printStackTrace();
         }

         return var2;
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
}
