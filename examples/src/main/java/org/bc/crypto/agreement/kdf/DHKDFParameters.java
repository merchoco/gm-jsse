package org.bc.crypto.agreement.kdf;

import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.crypto.DerivationParameters;

public class DHKDFParameters implements DerivationParameters {
   private ASN1ObjectIdentifier algorithm;
   private int keySize;
   private byte[] z;
   private byte[] extraInfo;

   public DHKDFParameters(DERObjectIdentifier var1, int var2, byte[] var3) {
      this(var1, var2, var3, (byte[])null);
   }

   public DHKDFParameters(DERObjectIdentifier var1, int var2, byte[] var3, byte[] var4) {
      this.algorithm = new ASN1ObjectIdentifier(var1.getId());
      this.keySize = var2;
      this.z = var3;
      this.extraInfo = var4;
   }

   public ASN1ObjectIdentifier getAlgorithm() {
      return this.algorithm;
   }

   public int getKeySize() {
      return this.keySize;
   }

   public byte[] getZ() {
      return this.z;
   }

   public byte[] getExtraInfo() {
      return this.extraInfo;
   }
}
