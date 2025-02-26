package org.bc.asn1.x509;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERSequence;

public class AttributeCertificateInfo extends ASN1Object {
   private ASN1Integer version;
   private Holder holder;
   private AttCertIssuer issuer;
   private AlgorithmIdentifier signature;
   private ASN1Integer serialNumber;
   private AttCertValidityPeriod attrCertValidityPeriod;
   private ASN1Sequence attributes;
   private DERBitString issuerUniqueID;
   private Extensions extensions;

   public static AttributeCertificateInfo getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public static AttributeCertificateInfo getInstance(Object var0) {
      if (var0 instanceof AttributeCertificateInfo) {
         return (AttributeCertificateInfo)var0;
      } else {
         return var0 != null ? new AttributeCertificateInfo(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private AttributeCertificateInfo(ASN1Sequence var1) {
      if (var1.size() >= 7 && var1.size() <= 9) {
         this.version = ASN1Integer.getInstance(var1.getObjectAt(0));
         this.holder = Holder.getInstance(var1.getObjectAt(1));
         this.issuer = AttCertIssuer.getInstance(var1.getObjectAt(2));
         this.signature = AlgorithmIdentifier.getInstance(var1.getObjectAt(3));
         this.serialNumber = ASN1Integer.getInstance(var1.getObjectAt(4));
         this.attrCertValidityPeriod = AttCertValidityPeriod.getInstance(var1.getObjectAt(5));
         this.attributes = ASN1Sequence.getInstance(var1.getObjectAt(6));

         for(int var2 = 7; var2 < var1.size(); ++var2) {
            ASN1Encodable var3 = var1.getObjectAt(var2);
            if (var3 instanceof DERBitString) {
               this.issuerUniqueID = DERBitString.getInstance(var1.getObjectAt(var2));
            } else if (var3 instanceof ASN1Sequence || var3 instanceof Extensions) {
               this.extensions = Extensions.getInstance(var1.getObjectAt(var2));
            }
         }

      } else {
         throw new IllegalArgumentException("Bad sequence size: " + var1.size());
      }
   }

   public ASN1Integer getVersion() {
      return this.version;
   }

   public Holder getHolder() {
      return this.holder;
   }

   public AttCertIssuer getIssuer() {
      return this.issuer;
   }

   public AlgorithmIdentifier getSignature() {
      return this.signature;
   }

   public ASN1Integer getSerialNumber() {
      return this.serialNumber;
   }

   public AttCertValidityPeriod getAttrCertValidityPeriod() {
      return this.attrCertValidityPeriod;
   }

   public ASN1Sequence getAttributes() {
      return this.attributes;
   }

   public DERBitString getIssuerUniqueID() {
      return this.issuerUniqueID;
   }

   public Extensions getExtensions() {
      return this.extensions;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.version);
      var1.add(this.holder);
      var1.add(this.issuer);
      var1.add(this.signature);
      var1.add(this.serialNumber);
      var1.add(this.attrCertValidityPeriod);
      var1.add(this.attributes);
      if (this.issuerUniqueID != null) {
         var1.add(this.issuerUniqueID);
      }

      if (this.extensions != null) {
         var1.add(this.extensions);
      }

      return new DERSequence(var1);
   }
}
