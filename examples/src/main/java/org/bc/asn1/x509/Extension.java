package org.bc.asn1.x509;

import java.io.IOException;
import org.bc.asn1.ASN1Boolean;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DEROctetString;

public class Extension {
   public static final ASN1ObjectIdentifier subjectDirectoryAttributes = new ASN1ObjectIdentifier("2.5.29.9");
   public static final ASN1ObjectIdentifier subjectKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.14");
   public static final ASN1ObjectIdentifier keyUsage = new ASN1ObjectIdentifier("2.5.29.15");
   public static final ASN1ObjectIdentifier privateKeyUsagePeriod = new ASN1ObjectIdentifier("2.5.29.16");
   public static final ASN1ObjectIdentifier subjectAlternativeName = new ASN1ObjectIdentifier("2.5.29.17");
   public static final ASN1ObjectIdentifier issuerAlternativeName = new ASN1ObjectIdentifier("2.5.29.18");
   public static final ASN1ObjectIdentifier basicConstraints = new ASN1ObjectIdentifier("2.5.29.19");
   public static final ASN1ObjectIdentifier cRLNumber = new ASN1ObjectIdentifier("2.5.29.20");
   public static final ASN1ObjectIdentifier reasonCode = new ASN1ObjectIdentifier("2.5.29.21");
   public static final ASN1ObjectIdentifier instructionCode = new ASN1ObjectIdentifier("2.5.29.23");
   public static final ASN1ObjectIdentifier invalidityDate = new ASN1ObjectIdentifier("2.5.29.24");
   public static final ASN1ObjectIdentifier deltaCRLIndicator = new ASN1ObjectIdentifier("2.5.29.27");
   public static final ASN1ObjectIdentifier issuingDistributionPoint = new ASN1ObjectIdentifier("2.5.29.28");
   public static final ASN1ObjectIdentifier certificateIssuer = new ASN1ObjectIdentifier("2.5.29.29");
   public static final ASN1ObjectIdentifier nameConstraints = new ASN1ObjectIdentifier("2.5.29.30");
   public static final ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");
   public static final ASN1ObjectIdentifier certificatePolicies = new ASN1ObjectIdentifier("2.5.29.32");
   public static final ASN1ObjectIdentifier policyMappings = new ASN1ObjectIdentifier("2.5.29.33");
   public static final ASN1ObjectIdentifier authorityKeyIdentifier = new ASN1ObjectIdentifier("2.5.29.35");
   public static final ASN1ObjectIdentifier policyConstraints = new ASN1ObjectIdentifier("2.5.29.36");
   public static final ASN1ObjectIdentifier extendedKeyUsage = new ASN1ObjectIdentifier("2.5.29.37");
   public static final ASN1ObjectIdentifier freshestCRL = new ASN1ObjectIdentifier("2.5.29.46");
   public static final ASN1ObjectIdentifier inhibitAnyPolicy = new ASN1ObjectIdentifier("2.5.29.54");
   public static final ASN1ObjectIdentifier authorityInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.1");
   public static final ASN1ObjectIdentifier subjectInfoAccess = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.11");
   public static final ASN1ObjectIdentifier logoType = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.12");
   public static final ASN1ObjectIdentifier biometricInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2");
   public static final ASN1ObjectIdentifier qCStatements = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");
   public static final ASN1ObjectIdentifier auditIdentity = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.4");
   public static final ASN1ObjectIdentifier noRevAvail = new ASN1ObjectIdentifier("2.5.29.56");
   public static final ASN1ObjectIdentifier targetInformation = new ASN1ObjectIdentifier("2.5.29.55");
   private ASN1ObjectIdentifier extnId;
   boolean critical;
   ASN1OctetString value;

   public Extension(ASN1ObjectIdentifier var1, ASN1Boolean var2, ASN1OctetString var3) {
      this(var1, var2.isTrue(), var3);
   }

   public Extension(ASN1ObjectIdentifier var1, boolean var2, byte[] var3) {
      this(var1, var2, (ASN1OctetString)(new DEROctetString(var3)));
   }

   public Extension(ASN1ObjectIdentifier var1, boolean var2, ASN1OctetString var3) {
      this.extnId = var1;
      this.critical = var2;
      this.value = var3;
   }

   public ASN1ObjectIdentifier getExtnId() {
      return this.extnId;
   }

   public boolean isCritical() {
      return this.critical;
   }

   public ASN1OctetString getExtnValue() {
      return this.value;
   }

   public ASN1Encodable getParsedValue() {
      return convertValueToObject(this);
   }

   public int hashCode() {
      return this.isCritical() ? this.getExtnValue().hashCode() : ~this.getExtnValue().hashCode();
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof Extension)) {
         return false;
      } else {
         Extension var2 = (Extension)var1;
         return var2.getExtnValue().equals(this.getExtnValue()) && var2.isCritical() == this.isCritical();
      }
   }

   private static ASN1Primitive convertValueToObject(Extension var0) throws IllegalArgumentException {
      try {
         return ASN1Primitive.fromByteArray(var0.getExtnValue().getOctets());
      } catch (IOException var2) {
         throw new IllegalArgumentException("can't convert extension: " + var2);
      }
   }
}
