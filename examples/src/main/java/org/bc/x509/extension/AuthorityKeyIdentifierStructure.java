package org.bc.x509.extension;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import org.bc.asn1.ASN1InputStream;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.x509.AuthorityKeyIdentifier;
import org.bc.asn1.x509.Extension;
import org.bc.asn1.x509.GeneralName;
import org.bc.asn1.x509.GeneralNames;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x509.X509Extension;
import org.bc.asn1.x509.X509Extensions;
import org.bc.jce.PrincipalUtil;

/** @deprecated */
public class AuthorityKeyIdentifierStructure extends AuthorityKeyIdentifier {
   public AuthorityKeyIdentifierStructure(byte[] var1) throws IOException {
      super((ASN1Sequence)X509ExtensionUtil.fromExtensionValue(var1));
   }

   /** @deprecated */
   public AuthorityKeyIdentifierStructure(X509Extension var1) {
      super((ASN1Sequence)var1.getParsedValue());
   }

   public AuthorityKeyIdentifierStructure(Extension var1) {
      super((ASN1Sequence)var1.getParsedValue());
   }

   private static ASN1Sequence fromCertificate(X509Certificate var0) throws CertificateParsingException {
      try {
         GeneralName var1;
         if (var0.getVersion() != 3) {
            var1 = new GeneralName(PrincipalUtil.getIssuerX509Principal(var0));
            SubjectPublicKeyInfo var5 = new SubjectPublicKeyInfo((ASN1Sequence)(new ASN1InputStream(var0.getPublicKey().getEncoded())).readObject());
            return (ASN1Sequence)(new AuthorityKeyIdentifier(var5, new GeneralNames(var1), var0.getSerialNumber())).toASN1Object();
         } else {
            var1 = new GeneralName(PrincipalUtil.getIssuerX509Principal(var0));
            byte[] var2 = var0.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId());
            if (var2 != null) {
               ASN1OctetString var6 = (ASN1OctetString)X509ExtensionUtil.fromExtensionValue(var2);
               return (ASN1Sequence)(new AuthorityKeyIdentifier(var6.getOctets(), new GeneralNames(var1), var0.getSerialNumber())).toASN1Object();
            } else {
               SubjectPublicKeyInfo var3 = new SubjectPublicKeyInfo((ASN1Sequence)(new ASN1InputStream(var0.getPublicKey().getEncoded())).readObject());
               return (ASN1Sequence)(new AuthorityKeyIdentifier(var3, new GeneralNames(var1), var0.getSerialNumber())).toASN1Object();
            }
         }
      } catch (Exception var4) {
         throw new CertificateParsingException("Exception extracting certificate details: " + var4.toString());
      }
   }

   private static ASN1Sequence fromKey(PublicKey var0) throws InvalidKeyException {
      try {
         SubjectPublicKeyInfo var1 = new SubjectPublicKeyInfo((ASN1Sequence)(new ASN1InputStream(var0.getEncoded())).readObject());
         return (ASN1Sequence)(new AuthorityKeyIdentifier(var1)).toASN1Object();
      } catch (Exception var2) {
         throw new InvalidKeyException("can't process key: " + var2);
      }
   }

   public AuthorityKeyIdentifierStructure(X509Certificate var1) throws CertificateParsingException {
      super(fromCertificate(var1));
   }

   public AuthorityKeyIdentifierStructure(PublicKey var1) throws InvalidKeyException {
      super(fromKey(var1));
   }
}
