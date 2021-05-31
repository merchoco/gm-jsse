package org.bc.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.Date;
import java.util.Iterator;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1GeneralizedTime;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.AttCertIssuer;
import org.bc.asn1.x509.Attribute;
import org.bc.asn1.x509.AttributeCertificate;
import org.bc.asn1.x509.AttributeCertificateInfo;
import org.bc.asn1.x509.V2AttributeCertificateInfoGenerator;
import org.bc.asn1.x509.X509ExtensionsGenerator;

/** @deprecated */
public class X509V2AttributeCertificateGenerator {
   private V2AttributeCertificateInfoGenerator acInfoGen = new V2AttributeCertificateInfoGenerator();
   private DERObjectIdentifier sigOID;
   private AlgorithmIdentifier sigAlgId;
   private String signatureAlgorithm;
   private X509ExtensionsGenerator extGenerator = new X509ExtensionsGenerator();

   public void reset() {
      this.acInfoGen = new V2AttributeCertificateInfoGenerator();
      this.extGenerator.reset();
   }

   public void setHolder(AttributeCertificateHolder var1) {
      this.acInfoGen.setHolder(var1.holder);
   }

   public void setIssuer(AttributeCertificateIssuer var1) {
      this.acInfoGen.setIssuer(AttCertIssuer.getInstance(var1.form));
   }

   public void setSerialNumber(BigInteger var1) {
      this.acInfoGen.setSerialNumber(new ASN1Integer(var1));
   }

   public void setNotBefore(Date var1) {
      this.acInfoGen.setStartDate(new ASN1GeneralizedTime(var1));
   }

   public void setNotAfter(Date var1) {
      this.acInfoGen.setEndDate(new ASN1GeneralizedTime(var1));
   }

   public void setSignatureAlgorithm(String var1) {
      this.signatureAlgorithm = var1;

      try {
         this.sigOID = X509Util.getAlgorithmOID(var1);
      } catch (Exception var3) {
         throw new IllegalArgumentException("Unknown signature type requested");
      }

      this.sigAlgId = X509Util.getSigAlgID(this.sigOID, var1);
      this.acInfoGen.setSignature(this.sigAlgId);
   }

   public void addAttribute(X509Attribute var1) {
      this.acInfoGen.addAttribute(Attribute.getInstance(var1.toASN1Object()));
   }

   public void setIssuerUniqueId(boolean[] var1) {
      throw new RuntimeException("not implemented (yet)");
   }

   public void addExtension(String var1, boolean var2, ASN1Encodable var3) throws IOException {
      this.extGenerator.addExtension(new ASN1ObjectIdentifier(var1), var2, var3);
   }

   public void addExtension(String var1, boolean var2, byte[] var3) {
      this.extGenerator.addExtension(new ASN1ObjectIdentifier(var1), var2, var3);
   }

   /** @deprecated */
   public X509AttributeCertificate generateCertificate(PrivateKey var1, String var2) throws NoSuchProviderException, SecurityException, SignatureException, InvalidKeyException {
      return this.generateCertificate(var1, var2, (SecureRandom)null);
   }

   /** @deprecated */
   public X509AttributeCertificate generateCertificate(PrivateKey var1, String var2, SecureRandom var3) throws NoSuchProviderException, SecurityException, SignatureException, InvalidKeyException {
      try {
         return this.generate(var1, var2, var3);
      } catch (NoSuchProviderException var5) {
         throw var5;
      } catch (SignatureException var6) {
         throw var6;
      } catch (InvalidKeyException var7) {
         throw var7;
      } catch (GeneralSecurityException var8) {
         throw new SecurityException("exception creating certificate: " + var8);
      }
   }

   public X509AttributeCertificate generate(PrivateKey var1, String var2) throws CertificateEncodingException, IllegalStateException, NoSuchProviderException, SignatureException, InvalidKeyException, NoSuchAlgorithmException {
      return this.generate(var1, var2, (SecureRandom)null);
   }

   public X509AttributeCertificate generate(PrivateKey var1, String var2, SecureRandom var3) throws CertificateEncodingException, IllegalStateException, NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
      if (!this.extGenerator.isEmpty()) {
         this.acInfoGen.setExtensions(this.extGenerator.generate());
      }

      AttributeCertificateInfo var4 = this.acInfoGen.generateAttributeCertificateInfo();
      ASN1EncodableVector var5 = new ASN1EncodableVector();
      var5.add(var4);
      var5.add(this.sigAlgId);

      try {
         var5.add(new DERBitString(X509Util.calculateSignature(this.sigOID, this.signatureAlgorithm, var2, var1, var3, var4)));
         return new X509V2AttributeCertificate(new AttributeCertificate(new DERSequence(var5)));
      } catch (IOException var7) {
         throw new ExtCertificateEncodingException("constructed invalid certificate", var7);
      }
   }

   public Iterator getSignatureAlgNames() {
      return X509Util.getAlgNames();
   }
}
