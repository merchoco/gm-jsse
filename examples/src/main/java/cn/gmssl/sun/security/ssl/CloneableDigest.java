package cn.gmssl.sun.security.ssl;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class CloneableDigest extends MessageDigest implements Cloneable {
   private final MessageDigest[] digests;

   private CloneableDigest(MessageDigest var1, int var2, String var3) throws NoSuchAlgorithmException {
      super(var3);
      this.digests = new MessageDigest[var2];
      this.digests[0] = var1;

      for(int var4 = 1; var4 < var2; ++var4) {
         this.digests[var4] = JsseJce.getMessageDigest(var3);
      }

   }

   static MessageDigest getDigest(String var0, int var1) throws NoSuchAlgorithmException {
      MessageDigest var2 = JsseJce.getMessageDigest(var0);

      try {
         var2.clone();
         return var2;
      } catch (CloneNotSupportedException var4) {
         return new CloneableDigest(var2, var1, var0);
      }
   }

   private void checkState() {
   }

   protected int engineGetDigestLength() {
      this.checkState();
      return this.digests[0].getDigestLength();
   }

   protected void engineUpdate(byte var1) {
      this.checkState();

      for(int var2 = 0; var2 < this.digests.length && this.digests[var2] != null; ++var2) {
         this.digests[var2].update(var1);
      }

   }

   protected void engineUpdate(byte[] var1, int var2, int var3) {
      this.checkState();

      for(int var4 = 0; var4 < this.digests.length && this.digests[var4] != null; ++var4) {
         this.digests[var4].update(var1, var2, var3);
      }

   }

   protected byte[] engineDigest() {
      this.checkState();
      byte[] var1 = this.digests[0].digest();
      this.digestReset();
      return var1;
   }

   protected int engineDigest(byte[] var1, int var2, int var3) throws DigestException {
      this.checkState();
      int var4 = this.digests[0].digest(var1, var2, var3);
      this.digestReset();
      return var4;
   }

   private void digestReset() {
      for(int var1 = 1; var1 < this.digests.length && this.digests[var1] != null; ++var1) {
         this.digests[var1].reset();
      }

   }

   protected void engineReset() {
      this.checkState();

      for(int var1 = 0; var1 < this.digests.length && this.digests[var1] != null; ++var1) {
         this.digests[var1].reset();
      }

   }

   public Object clone() {
      this.checkState();

      for(int var1 = this.digests.length - 1; var1 >= 0; --var1) {
         if (this.digests[var1] != null) {
            MessageDigest var2 = this.digests[var1];
            this.digests[var1] = null;
            return var2;
         }
      }

      throw new InternalError();
   }
}
