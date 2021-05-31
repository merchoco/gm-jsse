package org.bc.asn1.cms;

import java.math.BigInteger;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x500.X500Name;
import org.bc.asn1.x509.Certificate;
import org.bc.asn1.x509.X509CertificateStructure;
import org.bc.asn1.x509.X509Name;

public class IssuerAndSerialNumber extends ASN1Object {
   private X500Name name;
   private ASN1Integer serialNumber;

   public static IssuerAndSerialNumber getInstance(Object var0) {
      if (var0 instanceof IssuerAndSerialNumber) {
         return (IssuerAndSerialNumber)var0;
      } else {
         return var0 != null ? new IssuerAndSerialNumber(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public IssuerAndSerialNumber(ASN1Sequence var1) {
      this.name = X500Name.getInstance(var1.getObjectAt(0));
      this.serialNumber = (ASN1Integer)var1.getObjectAt(1);
   }

   public IssuerAndSerialNumber(Certificate var1) {
      this.name = var1.getIssuer();
      this.serialNumber = var1.getSerialNumber();
   }

   public IssuerAndSerialNumber(X509CertificateStructure var1) {
      this.name = var1.getIssuer();
      this.serialNumber = var1.getSerialNumber();
   }

   public IssuerAndSerialNumber(X500Name var1, BigInteger var2) {
      this.name = var1;
      this.serialNumber = new ASN1Integer(var2);
   }

   /** @deprecated */
   public IssuerAndSerialNumber(X509Name var1, BigInteger var2) {
      this.name = X500Name.getInstance(var1);
      this.serialNumber = new ASN1Integer(var2);
   }

   /** @deprecated */
   public IssuerAndSerialNumber(X509Name var1, ASN1Integer var2) {
      this.name = X500Name.getInstance(var1);
      this.serialNumber = var2;
   }

   public X500Name getName() {
      return this.name;
   }

   public ASN1Integer getSerialNumber() {
      return this.serialNumber;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.name);
      var1.add(this.serialNumber);
      return new DERSequence(var1);
   }
}
