package org.bc.crypto.parsers;

import java.io.IOException;
import java.io.InputStream;
import org.bc.crypto.KeyParser;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPublicKeyParameters;

public class ECIESPublicKeyParser implements KeyParser {
   private ECDomainParameters ecParams;

   public ECIESPublicKeyParser(ECDomainParameters var1) {
      this.ecParams = var1;
   }

   public AsymmetricKeyParameter readKey(InputStream var1) throws IOException {
      int var3 = var1.read();
      byte[] var2;
      switch(var3) {
      case 0:
         throw new IOException("Sender's public key invalid.");
      case 1:
      case 5:
      default:
         throw new IOException("Sender's public key has invalid point encoding 0x" + Integer.toString(var3, 16));
      case 2:
      case 3:
         var2 = new byte[1 + (this.ecParams.getCurve().getFieldSize() + 7) / 8];
         break;
      case 4:
      case 6:
      case 7:
         var2 = new byte[1 + 2 * ((this.ecParams.getCurve().getFieldSize() + 7) / 8)];
      }

      var2[0] = (byte)var3;
      var1.read(var2, 1, var2.length - 1);
      return new ECPublicKeyParameters(this.ecParams.getCurve().decodePoint(var2), this.ecParams);
   }
}
