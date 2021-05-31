package org.bc.crypto.tls;

import java.io.IOException;
import org.bc.crypto.BlockCipher;
import org.bc.crypto.Digest;
import org.bc.crypto.StreamCipher;
import org.bc.crypto.digests.MD5Digest;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.digests.SHA256Digest;
import org.bc.crypto.digests.SHA384Digest;
import org.bc.crypto.engines.AESFastEngine;
import org.bc.crypto.engines.DESedeEngine;
import org.bc.crypto.engines.RC4Engine;
import org.bc.crypto.modes.CBCBlockCipher;

public class DefaultTlsCipherFactory implements TlsCipherFactory {
   public TlsCipher createCipher(TlsClientContext var1, int var2, int var3) throws IOException {
      switch(var2) {
      case 2:
         return this.createRC4Cipher(var1, 16, var3);
      case 3:
      case 4:
      case 5:
      case 6:
      default:
         throw new TlsFatalAlert((short)80);
      case 7:
         return this.createDESedeCipher(var1, 24, var3);
      case 8:
         return this.createAESCipher(var1, 16, var3);
      case 9:
         return this.createAESCipher(var1, 32, var3);
      }
   }

   protected TlsCipher createAESCipher(TlsClientContext var1, int var2, int var3) throws IOException {
      return new TlsBlockCipher(var1, this.createAESBlockCipher(), this.createAESBlockCipher(), this.createDigest(var3), this.createDigest(var3), var2);
   }

   protected TlsCipher createRC4Cipher(TlsClientContext var1, int var2, int var3) throws IOException {
      return new TlsStreamCipher(var1, this.createRC4StreamCipher(), this.createRC4StreamCipher(), this.createDigest(var3), this.createDigest(var3), var2);
   }

   protected TlsCipher createDESedeCipher(TlsClientContext var1, int var2, int var3) throws IOException {
      return new TlsBlockCipher(var1, this.createDESedeBlockCipher(), this.createDESedeBlockCipher(), this.createDigest(var3), this.createDigest(var3), var2);
   }

   protected StreamCipher createRC4StreamCipher() {
      return new RC4Engine();
   }

   protected BlockCipher createAESBlockCipher() {
      return new CBCBlockCipher(new AESFastEngine());
   }

   protected BlockCipher createDESedeBlockCipher() {
      return new CBCBlockCipher(new DESedeEngine());
   }

   protected Digest createDigest(int var1) throws IOException {
      switch(var1) {
      case 1:
         return new MD5Digest();
      case 2:
         return new SHA1Digest();
      case 3:
         return new SHA256Digest();
      case 4:
         return new SHA384Digest();
      default:
         throw new TlsFatalAlert((short)80);
      }
   }
}
