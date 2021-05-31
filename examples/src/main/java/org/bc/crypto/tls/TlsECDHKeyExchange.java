package org.bc.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.agreement.ECDHBasicAgreement;
import org.bc.crypto.generators.ECKeyPairGenerator;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECKeyGenerationParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.crypto.util.PublicKeyFactory;
import org.bc.util.BigIntegers;

class TlsECDHKeyExchange implements TlsKeyExchange {
   protected TlsClientContext context;
   protected int keyExchange;
   protected TlsSigner tlsSigner;
   protected AsymmetricKeyParameter serverPublicKey;
   protected ECPublicKeyParameters ecAgreeServerPublicKey;
   protected TlsAgreementCredentials agreementCredentials;
   protected ECPrivateKeyParameters ecAgreeClientPrivateKey = null;

   TlsECDHKeyExchange(TlsClientContext var1, int var2) {
      switch(var2) {
      case 16:
      case 18:
         this.tlsSigner = null;
         break;
      case 17:
         this.tlsSigner = new TlsECDSASigner();
         break;
      case 19:
         this.tlsSigner = new TlsRSASigner();
         break;
      default:
         throw new IllegalArgumentException("unsupported key exchange algorithm");
      }

      this.context = var1;
      this.keyExchange = var2;
   }

   public void skipServerCertificate() throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void processServerCertificate(Certificate var1) throws IOException {
      org.bc.asn1.x509.Certificate var2 = var1.certs[0];
      SubjectPublicKeyInfo var3 = var2.getSubjectPublicKeyInfo();

      try {
         this.serverPublicKey = PublicKeyFactory.createKey(var3);
      } catch (RuntimeException var6) {
         throw new TlsFatalAlert((short)43);
      }

      if (this.tlsSigner == null) {
         try {
            this.ecAgreeServerPublicKey = this.validateECPublicKey((ECPublicKeyParameters)this.serverPublicKey);
         } catch (ClassCastException var5) {
            throw new TlsFatalAlert((short)46);
         }

         TlsUtils.validateKeyUsage(var2, 8);
      } else {
         if (!this.tlsSigner.isValidPublicKey(this.serverPublicKey)) {
            throw new TlsFatalAlert((short)46);
         }

         TlsUtils.validateKeyUsage(var2, 128);
      }

   }

   public void skipServerKeyExchange() throws IOException {
   }

   public void processServerKeyExchange(InputStream var1) throws IOException {
      throw new TlsFatalAlert((short)10);
   }

   public void validateCertificateRequest(CertificateRequest var1) throws IOException {
      short[] var2 = var1.getCertificateTypes();
      int var3 = 0;

      while(var3 < var2.length) {
         switch(var2[var3]) {
         case 1:
         case 2:
         case 64:
         case 65:
         case 66:
            ++var3;
            break;
         default:
            throw new TlsFatalAlert((short)47);
         }
      }

   }

   public void skipClientCredentials() throws IOException {
      this.agreementCredentials = null;
   }

   public void processClientCredentials(TlsCredentials var1) throws IOException {
      if (var1 instanceof TlsAgreementCredentials) {
         this.agreementCredentials = (TlsAgreementCredentials)var1;
      } else if (!(var1 instanceof TlsSignerCredentials)) {
         throw new TlsFatalAlert((short)80);
      }

   }

   public void generateClientKeyExchange(OutputStream var1) throws IOException {
      if (this.agreementCredentials == null) {
         this.generateEphemeralClientKeyExchange(this.ecAgreeServerPublicKey.getParameters(), var1);
      }

   }

   public byte[] generatePremasterSecret() throws IOException {
      return this.agreementCredentials != null ? this.agreementCredentials.generateAgreement(this.ecAgreeServerPublicKey) : this.calculateECDHBasicAgreement(this.ecAgreeServerPublicKey, this.ecAgreeClientPrivateKey);
   }

   protected boolean areOnSameCurve(ECDomainParameters var1, ECDomainParameters var2) {
      return var1.getCurve().equals(var2.getCurve()) && var1.getG().equals(var2.getG()) && var1.getN().equals(var2.getN()) && var1.getH().equals(var2.getH());
   }

   protected byte[] externalizeKey(ECPublicKeyParameters var1) throws IOException {
      return var1.getQ().getEncoded();
   }

   protected AsymmetricCipherKeyPair generateECKeyPair(ECDomainParameters var1) {
      ECKeyPairGenerator var2 = new ECKeyPairGenerator();
      ECKeyGenerationParameters var3 = new ECKeyGenerationParameters(var1, this.context.getSecureRandom());
      var2.init(var3);
      return var2.generateKeyPair();
   }

   protected void generateEphemeralClientKeyExchange(ECDomainParameters var1, OutputStream var2) throws IOException {
      AsymmetricCipherKeyPair var3 = this.generateECKeyPair(var1);
      this.ecAgreeClientPrivateKey = (ECPrivateKeyParameters)var3.getPrivate();
      byte[] var4 = this.externalizeKey((ECPublicKeyParameters)var3.getPublic());
      TlsUtils.writeOpaque8(var4, var2);
   }

   protected byte[] calculateECDHBasicAgreement(ECPublicKeyParameters var1, ECPrivateKeyParameters var2) {
      ECDHBasicAgreement var3 = new ECDHBasicAgreement();
      var3.init(var2);
      BigInteger var4 = var3.calculateAgreement(var1);
      return BigIntegers.asUnsignedByteArray(var4);
   }

   protected ECPublicKeyParameters validateECPublicKey(ECPublicKeyParameters var1) throws IOException {
      return var1;
   }
}
