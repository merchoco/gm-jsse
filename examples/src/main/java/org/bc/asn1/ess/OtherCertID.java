package org.bc.asn1.ess;

import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERSequence;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.DigestInfo;
import org.bc.asn1.x509.IssuerSerial;

public class OtherCertID extends ASN1Object {
   private ASN1Encodable otherCertHash;
   private IssuerSerial issuerSerial;

   public static OtherCertID getInstance(Object var0) {
      if (var0 instanceof OtherCertID) {
         return (OtherCertID)var0;
      } else {
         return var0 != null ? new OtherCertID(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private OtherCertID(ASN1Sequence var1) {
      if (var1.size() >= 1 && var1.size() <= 2) {
         if (var1.getObjectAt(0).toASN1Primitive() instanceof ASN1OctetString) {
            this.otherCertHash = ASN1OctetString.getInstance(var1.getObjectAt(0));
         } else {
            this.otherCertHash = DigestInfo.getInstance(var1.getObjectAt(0));
         }

         if (var1.size() > 1) {
            this.issuerSerial = IssuerSerial.getInstance(var1.getObjectAt(1));
         }

      } else {
         throw new IllegalArgumentException("Bad sequence size: " + var1.size());
      }
   }

   public OtherCertID(AlgorithmIdentifier var1, byte[] var2) {
      this.otherCertHash = new DigestInfo(var1, var2);
   }

   public OtherCertID(AlgorithmIdentifier var1, byte[] var2, IssuerSerial var3) {
      this.otherCertHash = new DigestInfo(var1, var2);
      this.issuerSerial = var3;
   }

   public AlgorithmIdentifier getAlgorithmHash() {
      return this.otherCertHash.toASN1Primitive() instanceof ASN1OctetString ? new AlgorithmIdentifier("1.3.14.3.2.26") : DigestInfo.getInstance(this.otherCertHash).getAlgorithmId();
   }

   public byte[] getCertHash() {
      return this.otherCertHash.toASN1Primitive() instanceof ASN1OctetString ? ((ASN1OctetString)this.otherCertHash.toASN1Primitive()).getOctets() : DigestInfo.getInstance(this.otherCertHash).getDigest();
   }

   public IssuerSerial getIssuerSerial() {
      return this.issuerSerial;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.otherCertHash);
      if (this.issuerSerial != null) {
         var1.add(this.issuerSerial);
      }

      return new DERSequence(var1);
   }
}
