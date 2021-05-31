package org.bc.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import org.bc.crypto.Signer;
import org.bc.crypto.io.SignerInputStream;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPublicKeyParameters;

class TlsDHEKeyExchange extends TlsDHKeyExchange {
   TlsDHEKeyExchange(TlsClientContext var1, int var2) {
      super(var1, var2);
   }

   public void skipServerKeyExchange() throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void processServerKeyExchange(InputStream var1) throws IOException {
      SecurityParameters var2 = this.context.getSecurityParameters();
      Signer var3 = this.initSigner(this.tlsSigner, var2);
      SignerInputStream var4 = new SignerInputStream(var1, var3);
      byte[] var5 = TlsUtils.readOpaque16(var4);
      byte[] var6 = TlsUtils.readOpaque16(var4);
      byte[] var7 = TlsUtils.readOpaque16(var4);
      byte[] var8 = TlsUtils.readOpaque16(var1);
      if (!var3.verifySignature(var8)) {
         throw new TlsFatalAlert((short)42);
      } else {
         BigInteger var9 = new BigInteger(1, var5);
         BigInteger var10 = new BigInteger(1, var6);
         BigInteger var11 = new BigInteger(1, var7);
         this.dhAgreeServerPublicKey = this.validateDHPublicKey(new DHPublicKeyParameters(var11, new DHParameters(var9, var10)));
      }
   }

   protected Signer initSigner(TlsSigner var1, SecurityParameters var2) {
      Signer var3 = var1.createVerifyer(this.serverPublicKey);
      var3.update(var2.clientRandom, 0, var2.clientRandom.length);
      var3.update(var2.serverRandom, 0, var2.serverRandom.length);
      return var3;
   }
}
