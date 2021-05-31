package org.bc.crypto.tls;

public class TlsNullCipher implements TlsCipher {
   public byte[] encodePlaintext(short var1, byte[] var2, int var3, int var4) {
      return this.copyData(var2, var3, var4);
   }

   public byte[] decodeCiphertext(short var1, byte[] var2, int var3, int var4) {
      return this.copyData(var2, var3, var4);
   }

   protected byte[] copyData(byte[] var1, int var2, int var3) {
      byte[] var4 = new byte[var3];
      System.arraycopy(var1, var2, var4, 0, var3);
      return var4;
   }
}
