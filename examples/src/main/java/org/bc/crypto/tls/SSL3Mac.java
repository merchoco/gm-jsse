package org.bc.crypto.tls;

import org.bc.crypto.CipherParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.Mac;
import org.bc.crypto.params.KeyParameter;
import org.bc.util.Arrays;

public class SSL3Mac implements Mac {
   private static final byte IPAD = 54;
   private static final byte OPAD = 92;
   static final byte[] MD5_IPAD = genPad((byte)54, 48);
   static final byte[] MD5_OPAD = genPad((byte)92, 48);
   static final byte[] SHA1_IPAD = genPad((byte)54, 40);
   static final byte[] SHA1_OPAD = genPad((byte)92, 40);
   private Digest digest;
   private byte[] secret;
   private byte[] ipad;
   private byte[] opad;

   public SSL3Mac(Digest var1) {
      this.digest = var1;
      if (var1.getDigestSize() == 20) {
         this.ipad = SHA1_IPAD;
         this.opad = SHA1_OPAD;
      } else {
         this.ipad = MD5_IPAD;
         this.opad = MD5_OPAD;
      }

   }

   public String getAlgorithmName() {
      return this.digest.getAlgorithmName() + "/SSL3MAC";
   }

   public Digest getUnderlyingDigest() {
      return this.digest;
   }

   public void init(CipherParameters var1) {
      this.secret = Arrays.clone(((KeyParameter)var1).getKey());
      this.reset();
   }

   public int getMacSize() {
      return this.digest.getDigestSize();
   }

   public void update(byte var1) {
      this.digest.update(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.digest.update(var1, var2, var3);
   }

   public int doFinal(byte[] var1, int var2) {
      byte[] var3 = new byte[this.digest.getDigestSize()];
      this.digest.doFinal(var3, 0);
      this.digest.update(this.secret, 0, this.secret.length);
      this.digest.update(this.opad, 0, this.opad.length);
      this.digest.update(var3, 0, var3.length);
      int var4 = this.digest.doFinal(var1, var2);
      this.reset();
      return var4;
   }

   public void reset() {
      this.digest.reset();
      this.digest.update(this.secret, 0, this.secret.length);
      this.digest.update(this.ipad, 0, this.ipad.length);
   }

   private static byte[] genPad(byte var0, int var1) {
      byte[] var2 = new byte[var1];
      Arrays.fill(var2, var0);
      return var2;
   }
}
