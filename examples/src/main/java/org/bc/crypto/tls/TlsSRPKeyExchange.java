package org.bc.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.CryptoException;
import org.bc.crypto.Signer;
import org.bc.crypto.agreement.srp.SRP6Client;
import org.bc.crypto.agreement.srp.SRP6Util;
import org.bc.crypto.digests.SHA1Digest;
import org.bc.crypto.io.SignerInputStream;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.util.PublicKeyFactory;
import org.bc.util.BigIntegers;

class TlsSRPKeyExchange implements TlsKeyExchange {
   protected TlsClientContext context;
   protected int keyExchange;
   protected TlsSigner tlsSigner;
   protected byte[] identity;
   protected byte[] password;
   protected AsymmetricKeyParameter serverPublicKey = null;
   protected byte[] s = null;
   protected BigInteger B = null;
   protected SRP6Client srpClient = new SRP6Client();

   TlsSRPKeyExchange(TlsClientContext var1, int var2, byte[] var3, byte[] var4) {
      switch(var2) {
      case 21:
         this.tlsSigner = null;
         break;
      case 22:
         this.tlsSigner = new TlsDSSSigner();
         break;
      case 23:
         this.tlsSigner = new TlsRSASigner();
         break;
      default:
         throw new IllegalArgumentException("unsupported key exchange algorithm");
      }

      this.context = var1;
      this.keyExchange = var2;
      this.identity = var3;
      this.password = var4;
   }

   public void skipServerCertificate() throws IOException {
      if (this.tlsSigner != null) {
         throw new TlsFatalAlert((short)10);
      }
   }

   public void processServerCertificate(Certificate var1) throws IOException {
      if (this.tlsSigner == null) {
         throw new TlsFatalAlert((short)10);
      } else {
         org.bc.asn1.x509.Certificate var2 = var1.certs[0];
         SubjectPublicKeyInfo var3 = var2.getSubjectPublicKeyInfo();

         try {
            this.serverPublicKey = PublicKeyFactory.createKey(var3);
         } catch (RuntimeException var5) {
            throw new TlsFatalAlert((short)43);
         }

         if (!this.tlsSigner.isValidPublicKey(this.serverPublicKey)) {
            throw new TlsFatalAlert((short)46);
         } else {
            TlsUtils.validateKeyUsage(var2, 128);
         }
      }
   }

   public void skipServerKeyExchange() throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void processServerKeyExchange(InputStream var1) throws IOException {
      SecurityParameters var2 = this.context.getSecurityParameters();
      Object var3 = var1;
      Signer var4 = null;
      if (this.tlsSigner != null) {
         var4 = this.initSigner(this.tlsSigner, var2);
         var3 = new SignerInputStream(var1, var4);
      }

      byte[] var5 = TlsUtils.readOpaque16((InputStream)var3);
      byte[] var6 = TlsUtils.readOpaque16((InputStream)var3);
      byte[] var7 = TlsUtils.readOpaque8((InputStream)var3);
      byte[] var8 = TlsUtils.readOpaque16((InputStream)var3);
      if (var4 != null) {
         byte[] var9 = TlsUtils.readOpaque16(var1);
         if (!var4.verifySignature(var9)) {
            throw new TlsFatalAlert((short)42);
         }
      }

      BigInteger var13 = new BigInteger(1, var5);
      BigInteger var10 = new BigInteger(1, var6);
      this.s = var7;

      try {
         this.B = SRP6Util.validatePublicValue(var13, new BigInteger(1, var8));
      } catch (CryptoException var12) {
         throw new TlsFatalAlert((short)47);
      }

      this.srpClient.init(var13, var10, new SHA1Digest(), this.context.getSecureRandom());
   }

   public void validateCertificateRequest(CertificateRequest var1) throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void skipClientCredentials() throws IOException {
   }

   public void processClientCredentials(TlsCredentials var1) throws IOException {
      throw new TlsFatalAlert((short)80);
   }

   public void generateClientKeyExchange(OutputStream var1) throws IOException {
      byte[] var2 = BigIntegers.asUnsignedByteArray(this.srpClient.generateClientCredentials(this.s, this.identity, this.password));
      TlsUtils.writeOpaque16(var2, var1);
   }

   public byte[] generatePremasterSecret() throws IOException {
      try {
         return BigIntegers.asUnsignedByteArray(this.srpClient.calculateSecret(this.B));
      } catch (CryptoException var2) {
         throw new TlsFatalAlert((short)47);
      }
   }

   protected Signer initSigner(TlsSigner var1, SecurityParameters var2) {
      Signer var3 = var1.createVerifyer(this.serverPublicKey);
      var3.update(var2.clientRandom, 0, var2.clientRandom.length);
      var3.update(var2.serverRandom, 0, var2.serverRandom.length);
      return var3;
   }
}
