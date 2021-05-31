package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.math.BigInteger;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

final class PrivateKeyInfo {
   private static final BigInteger VERSION;
   private AlgorithmId algid;
   private byte[] privkey;

   static {
      VERSION = BigInteger.ZERO;
   }

   PrivateKeyInfo(byte[] var1) throws IOException {
      DerValue var2 = new DerValue(var1);
      if (var2.tag != 48) {
         throw new IOException("private key parse error: not a sequence");
      } else {
         BigInteger var3 = var2.data.getBigInteger();
         if (!var3.equals(VERSION)) {
            throw new IOException("version mismatch: (supported: " + VERSION + ", parsed: " + var3);
         } else {
            this.algid = AlgorithmId.parse(var2.data.getDerValue());
            this.privkey = var2.data.getOctetString();
         }
      }
   }

   AlgorithmId getAlgorithm() {
      return this.algid;
   }
}
