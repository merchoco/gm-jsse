package org.bc.crypto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;
import org.bc.crypto.util.PublicKeyFactory;

class TlsDHKeyExchange implements TlsKeyExchange {
   protected static final BigInteger ONE = BigInteger.valueOf(1L);
   protected static final BigInteger TWO = BigInteger.valueOf(2L);
   protected TlsClientContext context;
   protected int keyExchange;
   protected TlsSigner tlsSigner;
   protected AsymmetricKeyParameter serverPublicKey = null;
   protected DHPublicKeyParameters dhAgreeServerPublicKey = null;
   protected TlsAgreementCredentials agreementCredentials;
   protected DHPrivateKeyParameters dhAgreeClientPrivateKey = null;

   TlsDHKeyExchange(TlsClientContext var1, int var2) {
      switch(var2) {
      case 3:
         this.tlsSigner = new TlsDSSSigner();
         break;
      case 4:
      case 6:
      case 8:
      default:
         throw new IllegalArgumentException("unsupported key exchange algorithm");
      case 5:
         this.tlsSigner = new TlsRSASigner();
         break;
      case 7:
      case 9:
         this.tlsSigner = null;
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
            this.dhAgreeServerPublicKey = this.validateDHPublicKey((DHPublicKeyParameters)this.serverPublicKey);
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
         case 3:
         case 4:
         case 64:
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
         this.generateEphemeralClientKeyExchange(this.dhAgreeServerPublicKey.getParameters(), var1);
      }

   }

   public byte[] generatePremasterSecret() throws IOException {
      return this.agreementCredentials != null ? this.agreementCredentials.generateAgreement(this.dhAgreeServerPublicKey) : this.calculateDHBasicAgreement(this.dhAgreeServerPublicKey, this.dhAgreeClientPrivateKey);
   }

   protected boolean areCompatibleParameters(DHParameters var1, DHParameters var2) {
      return var1.getP().equals(var2.getP()) && var1.getG().equals(var2.getG());
   }

   protected byte[] calculateDHBasicAgreement(DHPublicKeyParameters var1, DHPrivateKeyParameters var2) {
      return TlsDHUtils.calculateDHBasicAgreement(var1, var2);
   }

   protected AsymmetricCipherKeyPair generateDHKeyPair(DHParameters var1) {
      return TlsDHUtils.generateDHKeyPair(this.context.getSecureRandom(), var1);
   }

   protected void generateEphemeralClientKeyExchange(DHParameters var1, OutputStream var2) throws IOException {
      this.dhAgreeClientPrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(this.context.getSecureRandom(), var1, var2);
   }

   protected DHPublicKeyParameters validateDHPublicKey(DHPublicKeyParameters var1) throws IOException {
      return TlsDHUtils.validateDHPublicKey(var1);
   }
}
