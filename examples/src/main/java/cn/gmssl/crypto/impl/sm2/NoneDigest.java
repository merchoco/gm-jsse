package cn.gmssl.crypto.impl.sm2;

import cn.gmssl.crypto.util.Debug;
import cn.gmssl.crypto.util.PrintUtil;
import java.io.ByteArrayOutputStream;
import org.bc.crypto.digests.GeneralDigest;

public class NoneDigest extends GeneralDigest {
   private ByteArrayOutputStream bout = new ByteArrayOutputStream();

   public NoneDigest() {
      this.reset();
   }

   public void update(byte var1) {
      this.bout.write(var1);
   }

   public void update(byte[] var1, int var2, int var3) {
      this.bout.write(var1, var2, var3);
   }

   public int doFinal(byte[] var1, int var2) {
      byte[] var3 = this.bout.toByteArray();
      if (Debug.sm2) {
         PrintUtil.printHex(var3, "buf");
         System.out.println("buf end");
         System.out.println("buf.length=" + var3.length);
      }

      if (var3.length == 32) {
         System.arraycopy(var3, 0, var1, var2, 32);
      }

      this.finish();
      this.reset();
      return var3.length;
   }

   public String getAlgorithmName() {
      return "Dump";
   }

   public int getDigestSize() {
      return 32;
   }

   public void reset() {
      super.reset();
      this.bout.reset();
   }

   protected void processWord(byte[] var1, int var2) {
   }

   protected void processLength(long var1) {
   }

   protected void processBlock() {
   }
}
