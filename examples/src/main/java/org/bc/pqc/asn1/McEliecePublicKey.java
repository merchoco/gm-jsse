package org.bc.pqc.asn1;

import java.math.BigInteger;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1Object;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.pqc.math.linearalgebra.GF2Matrix;

public class McEliecePublicKey extends ASN1Object {
   private ASN1ObjectIdentifier oid;
   private int n;
   private int t;
   private byte[] matrixG;

   public McEliecePublicKey(ASN1ObjectIdentifier var1, int var2, int var3, GF2Matrix var4) {
      this.oid = var1;
      this.n = var2;
      this.t = var3;
      this.matrixG = var4.getEncoded();
   }

   private McEliecePublicKey(ASN1Sequence var1) {
      this.oid = (ASN1ObjectIdentifier)var1.getObjectAt(0);
      BigInteger var2 = ((ASN1Integer)var1.getObjectAt(1)).getValue();
      this.n = var2.intValue();
      BigInteger var3 = ((ASN1Integer)var1.getObjectAt(2)).getValue();
      this.t = var3.intValue();
      this.matrixG = ((ASN1OctetString)var1.getObjectAt(3)).getOctets();
   }

   public ASN1ObjectIdentifier getOID() {
      return this.oid;
   }

   public int getN() {
      return this.n;
   }

   public int getT() {
      return this.t;
   }

   public GF2Matrix getG() {
      return new GF2Matrix(this.matrixG);
   }

   public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector var1 = new ASN1EncodableVector();
      var1.add(this.oid);
      var1.add(new ASN1Integer((long)this.n));
      var1.add(new ASN1Integer((long)this.t));
      var1.add(new DEROctetString(this.matrixG));
      return new DERSequence(var1);
   }

   public static McEliecePublicKey getInstance(Object var0) {
      if (var0 instanceof McEliecePublicKey) {
         return (McEliecePublicKey)var0;
      } else {
         return var0 != null ? new McEliecePublicKey(ASN1Sequence.getInstance(var0)) : null;
      }
   }
}
