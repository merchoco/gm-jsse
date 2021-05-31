package org.bc.ocsp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.DERNull;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.ocsp.CertID;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.jce.PrincipalUtil;
import org.bc.jce.X509Principal;

public class CertificateID {
   public static final String HASH_SHA1 = "1.3.14.3.2.26";
   private final CertID id;

   public CertificateID(CertID var1) {
      if (var1 == null) {
         throw new IllegalArgumentException("'id' cannot be null");
      } else {
         this.id = var1;
      }
   }

   public CertificateID(String var1, X509Certificate var2, BigInteger var3, String var4) throws OCSPException {
      AlgorithmIdentifier var5 = new AlgorithmIdentifier(new DERObjectIdentifier(var1), DERNull.INSTANCE);
      this.id = createCertID(var5, var2, new ASN1Integer(var3), var4);
   }

   public CertificateID(String var1, X509Certificate var2, BigInteger var3) throws OCSPException {
      this(var1, var2, var3, "BC");
   }

   public String getHashAlgOID() {
      return this.id.getHashAlgorithm().getObjectId().getId();
   }

   public byte[] getIssuerNameHash() {
      return this.id.getIssuerNameHash().getOctets();
   }

   public byte[] getIssuerKeyHash() {
      return this.id.getIssuerKeyHash().getOctets();
   }

   public BigInteger getSerialNumber() {
      return this.id.getSerialNumber().getValue();
   }

   public boolean matchesIssuer(X509Certificate var1, String var2) throws OCSPException {
      return createCertID(this.id.getHashAlgorithm(), var1, this.id.getSerialNumber(), var2).equals(this.id);
   }

   public CertID toASN1Object() {
      return this.id;
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof CertificateID)) {
         return false;
      } else {
         CertificateID var2 = (CertificateID)var1;
         return this.id.toASN1Primitive().equals(var2.id.toASN1Primitive());
      }
   }

   public int hashCode() {
      return this.id.toASN1Primitive().hashCode();
   }

   public static CertificateID deriveCertificateID(CertificateID var0, BigInteger var1) {
      return new CertificateID(new CertID(var0.id.getHashAlgorithm(), var0.id.getIssuerNameHash(), var0.id.getIssuerKeyHash(), new ASN1Integer(var1)));
   }

   private static CertID createCertID(AlgorithmIdentifier var0, X509Certificate var1, ASN1Integer var2, String var3) throws OCSPException {
      try {
         MessageDigest var4 = OCSPUtil.createDigestInstance(var0.getAlgorithm().getId(), var3);
         X509Principal var5 = PrincipalUtil.getSubjectX509Principal(var1);
         var4.update(var5.getEncoded());
         DEROctetString var6 = new DEROctetString(var4.digest());
         PublicKey var7 = var1.getPublicKey();
         ASN1InputStream var8 = new ASN1InputStream(var7.getEncoded());
         SubjectPublicKeyInfo var9 = SubjectPublicKeyInfo.getInstance(var8.readObject());
         var4.update(var9.getPublicKeyData().getBytes());
         DEROctetString var10 = new DEROctetString(var4.digest());
         return new CertID(var0, var6, var10, var2);
      } catch (Exception var11) {
         throw new OCSPException("problem creating ID: " + var11, var11);
      }
   }
}
