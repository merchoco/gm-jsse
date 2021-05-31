package org.bc.crypto.tls;

import org.bc.crypto.Digest;
import org.bc.crypto.digests.MD5Digest;
import org.bc.crypto.digests.SHA1Digest;

class CombinedHash implements Digest {
   protected TlsClientContext context;
   protected MD5Digest md5;
   protected SHA1Digest sha1;

   CombinedHash() {
      this.md5 = new MD5Digest();
      this.sha1 = new SHA1Digest();
   }

   CombinedHash(TlsClientContext var1) {
      this.context = var1;
      this.md5 = new MD5Digest();
      this.sha1 = new SHA1Digest();
   }

   CombinedHash(CombinedHash var1) {
      this.context = var1.context;
      this.md5 = new MD5Digest(var1.md5);
      this.sha1 = new SHA1Digest(var1.sha1);
   }

   public String getAlgorithmName() {
      return this.md5.getAlgorithmName() + " and " + this.sha1.getAlgorithmName();
   }

   public int getDigestSize() {
      return 36;
   }

   public void update(byte var1) {
      this.md5.update(var1);
      this.sha1.update(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.md5.update(var1, var2, var3);
      this.sha1.update(var1, var2, var3);
   }

   public int doFinal(byte[] var1, int var2) {
      if (this.context != null) {
         boolean var3 = this.context.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
         if (!var3) {
            this.ssl3Complete(this.md5, SSL3Mac.MD5_IPAD, SSL3Mac.MD5_OPAD);
            this.ssl3Complete(this.sha1, SSL3Mac.SHA1_IPAD, SSL3Mac.SHA1_OPAD);
         }
      }

      int var5 = this.md5.doFinal(var1, var2);
      int var4 = this.sha1.doFinal(var1, var2 + 16);
      return var5 + var4;
   }

   public void reset() {
      this.md5.reset();
      this.sha1.reset();
   }

   protected void ssl3Complete(Digest var1, byte[] var2, byte[] var3) {
      byte[] var4 = this.context.getSecurityParameters().masterSecret;
      var1.update(var4, 0, var4.length);
      var1.update(var2, 0, var2.length);
      byte[] var5 = new byte[var1.getDigestSize()];
      var1.doFinal(var5, 0);
      var1.update(var4, 0, var4.length);
      var1.update(var3, 0, var3.length);
      var1.update(var5, 0, var5.length);
   }
}
