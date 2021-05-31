package org.bc.crypto.tls;

import java.io.IOException;
import java.io.OutputStream;
import org.bc.crypto.InvalidCipherTextException;
import org.bc.crypto.encodings.PKCS1Encoding;
import org.bc.crypto.engines.RSABlindedEngine;
import org.bc.crypto.params.ParametersWithRandom;
import org.bc.crypto.params.RSAKeyParameters;

public class TlsRSAUtils {
   public static byte[] generateEncryptedPreMasterSecret(TlsClientContext var0, RSAKeyParameters var1, OutputStream var2) throws IOException {
      byte[] var3 = new byte[48];
      var0.getSecureRandom().nextBytes(var3);
      TlsUtils.writeVersion(var0.getClientVersion(), var3, 0);
      PKCS1Encoding var4 = new PKCS1Encoding(new RSABlindedEngine());
      var4.init(true, new ParametersWithRandom(var1, var0.getSecureRandom()));

      try {
         boolean var5 = var0.getServerVersion().getFullVersion() >= ProtocolVersion.TLSv10.getFullVersion();
         byte[] var6 = var4.processBlock(var3, 0, var3.length);
         if (var5) {
            TlsUtils.writeOpaque16(var6, var2);
         } else {
            var2.write(var6);
         }

         return var3;
      } catch (InvalidCipherTextException var7) {
         throw new TlsFatalAlert((short)80);
      }
   }
}
