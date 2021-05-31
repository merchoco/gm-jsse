package org.bc.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.bc.crypto.KeyParser;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPublicKeyParameters;

public class DHIESPublicKeyParser implements KeyParser {
   private DHParameters dhParams;

   public DHIESPublicKeyParser(DHParameters var1) {
      this.dhParams = var1;
   }

   public AsymmetricKeyParameter readKey(InputStream var1) throws IOException {
      byte[] var2 = new byte[(this.dhParams.getP().bitLength() + 7) / 8];
      var1.read(var2, 0, var2.length);
      return new DHPublicKeyParameters(new BigInteger(1, var2), this.dhParams);
   }
}
