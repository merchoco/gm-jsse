package org.bc.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import org.bc.crypto.Signer;
import org.bc.crypto.io.SignerInputStream;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.math.ec.ECPoint;

class TlsECDHEKeyExchange extends TlsECDHKeyExchange {
   TlsECDHEKeyExchange(TlsClientContext var1, int var2) {
      super(var1, var2);
   }

   public void skipServerKeyExchange() throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void processServerKeyExchange(InputStream var1) throws IOException {
      SecurityParameters var2 = this.context.getSecurityParameters();
      Signer var3 = this.initSigner(this.tlsSigner, var2);
      SignerInputStream var4 = new SignerInputStream(var1, var3);
      short var5 = TlsUtils.readUint8(var4);
      if (var5 == 3) {
         int var7 = TlsUtils.readUint16(var4);
         ECDomainParameters var6 = NamedCurve.getECParameters(var7);
         byte[] var10 = TlsUtils.readOpaque8(var4);
         byte[] var8 = TlsUtils.readOpaque16(var1);
         if (!var3.verifySignature(var8)) {
            throw new TlsFatalAlert((short)42);
         } else {
            ECPoint var9 = var6.getCurve().decodePoint(var10);
            this.ecAgreeServerPublicKey = this.validateECPublicKey(new ECPublicKeyParameters(var9, var6));
         }
      } else {
         throw new TlsFatalAlert((short)40);
      }
   }

   public void validateCertificateRequest(CertificateRequest var1) throws IOException {
      short[] var2 = var1.getCertificateTypes();
      int var3 = 0;

      while(var3 < var2.length) {
         switch(var2[var3]) {
         case 1:
         case 2:
         case 64:
            ++var3;
            break;
         default:
            throw new TlsFatalAlert((short)47);
         }
      }

   }

   public void processClientCredentials(TlsCredentials var1) throws IOException {
      if (!(var1 instanceof TlsSignerCredentials)) {
         throw new TlsFatalAlert((short)80);
      }
   }

   protected Signer initSigner(TlsSigner var1, SecurityParameters var2) {
      Signer var3 = var1.createVerifyer(this.serverPublicKey);
      var3.update(var2.clientRandom, 0, var2.clientRandom.length);
      var3.update(var2.serverRandom, 0, var2.serverRandom.length);
      return var3;
   }
}
