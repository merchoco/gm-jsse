package org.bc.crypto.tls;

import java.io.IOException;
import org.bc.crypto.Digest;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.params.KeyParameter;
import org.bc.util.Arrays;

public class TlsStreamCipher implements TlsCipher {
   protected TlsClientContext context;
   protected StreamCipher encryptCipher;
   protected StreamCipher decryptCipher;
   protected TlsMac writeMac;
   protected TlsMac readMac;

   public TlsStreamCipher(TlsClientContext var1, StreamCipher var2, StreamCipher var3, Digest var4, Digest var5, int var6) throws IOException {
      this.context = var1;
      this.encryptCipher = var2;
      this.decryptCipher = var3;
      int var7 = 2 * var6 + var4.getDigestSize() + var5.getDigestSize();
      SecurityParameters var8 = var1.getSecurityParameters();
      byte[] var9 = TlsUtils.PRF(var8.masterSecret, "key expansion", TlsUtils.concat(var8.serverRandom, var8.clientRandom), var7);
      byte var10 = 0;
      this.writeMac = new TlsMac(var1, var4, var9, var10, var4.getDigestSize());
      int var13 = var10 + var4.getDigestSize();
      this.readMac = new TlsMac(var1, var5, var9, var13, var5.getDigestSize());
      var13 += var5.getDigestSize();
      KeyParameter var11 = new KeyParameter(var9, var13, var6);
      var13 += var6;
      KeyParameter var12 = new KeyParameter(var9, var13, var6);
      var13 += var6;
      if (var13 != var7) {
         throw new TlsFatalAlert((short)80);
      } else {
         var2.init(true, var11);
         var3.init(true, var12);
      }
   }

   public byte[] encodePlaintext(short var1, byte[] var2, int var3, int var4) {
      byte[] var5 = this.writeMac.calculateMac(var1, var2, var3, var4);
      byte[] var6 = new byte[var4 + var5.length];
      this.encryptCipher.processBytes(var2, var3, var4, var6, 0);
      this.encryptCipher.processBytes(var5, 0, var5.length, var6, var4);
      return var6;
   }

   public byte[] decodeCiphertext(short var1, byte[] var2, int var3, int var4) throws IOException {
      byte[] var5 = new byte[var4];
      this.decryptCipher.processBytes(var2, var3, var4, var5, 0);
      int var6 = var5.length - this.readMac.getSize();
      byte[] var7 = this.copyData(var5, 0, var6);
      byte[] var8 = this.copyData(var5, var6, this.readMac.getSize());
      byte[] var9 = this.readMac.calculateMac(var1, var7, 0, var7.length);
      if (!Arrays.constantTimeAreEqual(var8, var9)) {
         throw new TlsFatalAlert((short)20);
      } else {
         return var7;
      }
   }

   protected byte[] copyData(byte[] var1, int var2, int var3) {
      byte[] var4 = new byte[var3];
      System.arraycopy(var1, var2, var4, 0, var3);
      return var4;
   }
}
