package org.bc.asn1.x509;

import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.ASN1TaggedObject;
import org.bc.asn1.DERSequence;

public class CertificatePolicies extends ASN1Object {
   private final PolicyInformation[] policyInformation;

   public static CertificatePolicies getInstance(Object var0) {
      if (var0 instanceof CertificatePolicies) {
         return (CertificatePolicies)var0;
      } else {
         return var0 != null ? new CertificatePolicies(ASN1Sequence.getInstance(var0)) : null;
      }
   }

   public static CertificatePolicies getInstance(ASN1TaggedObject var0, boolean var1) {
      return getInstance(ASN1Sequence.getInstance(var0, var1));
   }

   public CertificatePolicies(PolicyInformation var1) {
      this.policyInformation = new PolicyInformation[]{var1};
   }

   public CertificatePolicies(PolicyInformation[] var1) {
      this.policyInformation = var1;
   }

   private CertificatePolicies(ASN1Sequence var1) {
      this.policyInformation = new PolicyInformation[var1.size()];

      for(int var2 = 0; var2 != var1.size(); ++var2) {
         this.policyInformation[var2] = PolicyInformation.getInstance(var1.getObjectAt(var2));
      }

   }

   public PolicyInformation[] getPolicyInformation() {
      PolicyInformation[] var1 = new PolicyInformation[this.policyInformation.length];
      System.arraycopy(this.policyInformation, 0, var1, 0, this.policyInformation.length);
      return var1;
   }

   public ASN1Primitive toASN1Primitive() {
      return new DERSequence(this.policyInformation);
   }

   public String toString() {
      String var1 = null;

      for(int var2 = 0; var2 < this.policyInformation.length; ++var2) {
         if (var1 != null) {
            var1 = var1 + ", ";
         }

         var1 = var1 + this.policyInformation[var2];
      }

      return "CertificatePolicies: " + var1;
   }
}
