package org.bc.asn1.ess;

import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.nist.NISTObjectIdentifiers;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.IssuerSerial;

public class ESSCertIDv2 extends ASN1Object {
   private AlgorithmIdentifier hashAlgorithm;
   private byte[] certHash;
   private IssuerSerial issuerSerial;
   private static final AlgorithmIdentifier DEFAULT_ALG_ID;

   static {
      DEFAULT_ALG_ID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
   }

   public static ESSCertIDv2 getInstance(Object var0) {
      if (var0 instanceof ESSCertIDv2) {
         return (ESSCertIDv2)var0;
      } else {
         return var0 != null ? new ESSCertIDv2(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   private ESSCertIDv2(ASN1Sequence var1) {
      if (var1.size() > 3) {
         throw new IllegalArgumentException("Bad sequence size: " + var1.size());
      } else {
         int var2 = 0;
         if (var1.getObjectAt(0) instanceof ASN1OctetString) {
            this.hashAlgorithm = DEFAULT_ALG_ID;
         } else {
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(var1.getObjectAt(var2++).toASN1Primitive());
         }

         this.certHash = ASN1OctetString.getInstance(var1.getObjectAt(var2++).toASN1Primitive()).getOctets();
         if (var1.size() > var2) {
            this.issuerSerial = IssuerSerial.getInstance(var1.getObjectAt(var2));
         }

      }
   }

   public ESSCertIDv2(AlgorithmIdentifier var1, byte[] var2) {
      this(var1, var2, (IssuerSerial)null);
   }

   public ESSCertIDv2(AlgorithmIdentifier var1, byte[] var2, IssuerSerial var3) {
      if (var1 == null) {
         this.hashAlgorithm = DEFAULT_ALG_ID;
      } else {
         this.hashAlgorithm = var1;
      }

      this.certHash = var2;
      this.issuerSerial = var3;
   }

   public AlgorithmIdentifier getHashAlgorithm() {
      return this.hashAlgorithm;
   }

   public byte[] getCertHash() {
      return this.certHash;
   }

   public IssuerSerial getIssuerSerial() {
      return this.issuerSerial;
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      if (!this.hashAlgorithm.equals(DEFAULT_ALG_ID)) {
         var1.add(this.hashAlgorithm);
      }

      var1.add((new DEROctetString(this.certHash)).toASN1Primitive());
      if (this.issuerSerial != null) {
         var1.add(this.issuerSerial);
      }

      return new DERSequence(var1);
   }
}
