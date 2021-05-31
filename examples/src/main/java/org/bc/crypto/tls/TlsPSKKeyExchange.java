package org.bc.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.params.AsymmetricKeyParameter;
import org.bc.crypto.params.DHParameters;
import org.bc.crypto.params.DHPrivateKeyParameters;
import org.bc.crypto.params.DHPublicKeyParameters;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.crypto.util.PublicKeyFactory;

class TlsPSKKeyExchange implements TlsKeyExchange {
   protected TlsClientContext context;
   protected int keyExchange;
   protected TlsPSKIdentity pskIdentity;
   protected byte[] psk_identity_hint = null;
   protected DHPublicKeyParameters dhAgreeServerPublicKey = null;
   protected DHPrivateKeyParameters dhAgreeClientPrivateKey = null;
   protected AsymmetricKeyParameter serverPublicKey = null;
   protected RSAKeyParameters rsaServerPublicKey = null;
   protected byte[] premasterSecret;

   TlsPSKKeyExchange(TlsClientContext var1, int var2, TlsPSKIdentity var3) {
      switch(var2) {
      case 13:
      case 14:
      case 15:
         this.context = var1;
         this.keyExchange = var2;
         this.pskIdentity = var3;
         return;
      default:
         throw new IllegalArgumentException("unsupported key exchange algorithm");
      }
   }

   public void skipServerCertificate() throws IOException {
      if (this.keyExchange == 15) {
         throw new TlsFatalAlert((short)10);
      }
   }

   public void processServerCertificate(Certificate var1) throws IOException {
      if (this.keyExchange != 15) {
         throw new TlsFatalAlert((short)10);
      } else {
         org.bc.asn1.x509.Certificate var2 = var1.certs[0];
         SubjectPublicKeyInfo var3 = var2.getSubjectPublicKeyInfo();

         try {
            this.serverPublicKey = PublicKeyFactory.createKey(var3);
         } catch (RuntimeException var5) {
            throw new TlsFatalAlert((short)43);
         }

         if (this.serverPublicKey.isPrivate()) {
            throw new TlsFatalAlert((short)80);
         } else {
            this.rsaServerPublicKey = this.validateRSAPublicKey((RSAKeyParameters)this.serverPublicKey);
            TlsUtils.validateKeyUsage(var2, 32);
         }
      }
   }

   public void skipServerKeyExchange() throws IOException {
      if (this.keyExchange == 14) {
         throw new TlsFatalAlert((short)10);
      } else {
         this.psk_identity_hint = new byte[0];
      }
   }

   public void processServerKeyExchange(InputStream var1) throws IOException {
      this.psk_identity_hint = TlsUtils.readOpaque16(var1);
      if (this.keyExchange == 14) {
         byte[] var2 = TlsUtils.readOpaque16(var1);
         byte[] var3 = TlsUtils.readOpaque16(var1);
         byte[] var4 = TlsUtils.readOpaque16(var1);
         BigInteger var5 = new BigInteger(1, var2);
         BigInteger var6 = new BigInteger(1, var3);
         BigInteger var7 = new BigInteger(1, var4);
         this.dhAgreeServerPublicKey = TlsDHUtils.validateDHPublicKey(new DHPublicKeyParameters(var7, new DHParameters(var5, var6)));
      } else {
         int var10000 = this.psk_identity_hint.length;
      }

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
      if (this.psk_identity_hint != null && this.psk_identity_hint.length != 0) {
         this.pskIdentity.notifyIdentityHint(this.psk_identity_hint);
      } else {
         this.pskIdentity.skipIdentityHint();
      }

      byte[] var2 = this.pskIdentity.getPSKIdentity();
      TlsUtils.writeOpaque16(var2, var1);
      if (this.keyExchange == 15) {
         this.premasterSecret = TlsRSAUtils.generateEncryptedPreMasterSecret(this.context, this.rsaServerPublicKey, var1);
      } else if (this.keyExchange == 14) {
         this.dhAgreeClientPrivateKey = TlsDHUtils.generateEphemeralClientKeyExchange(this.context.getSecureRandom(), this.dhAgreeServerPublicKey.getParameters(), var1);
      }

   }

   public byte[] generatePremasterSecret() throws IOException {
      byte[] var1 = this.pskIdentity.getPSK();
      byte[] var2 = this.generateOtherSecret(var1.length);
      ByteArrayOutputStream var3 = new ByteArrayOutputStream(4 + var2.length + var1.length);
      TlsUtils.writeOpaque16(var2, var3);
      TlsUtils.writeOpaque16(var1, var3);
      return var3.toByteArray();
   }

   protected byte[] generateOtherSecret(int var1) {
      if (this.keyExchange == 14) {
         return TlsDHUtils.calculateDHBasicAgreement(this.dhAgreeServerPublicKey, this.dhAgreeClientPrivateKey);
      } else {
         return this.keyExchange == 15 ? this.premasterSecret : new byte[var1];
      }
   }

   protected RSAKeyParameters validateRSAPublicKey(RSAKeyParameters var1) throws IOException {
      if (!var1.getExponent().isProbablePrime(2)) {
         throw new TlsFatalAlert((short)47);
      } else {
         return var1;
      }
   }
}
