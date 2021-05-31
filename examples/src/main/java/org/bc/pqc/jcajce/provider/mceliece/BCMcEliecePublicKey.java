package org.bc.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PublicKey;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERNull;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.CipherParameters;
import org.bc.pqc.asn1.McEliecePublicKey;
import org.bc.pqc.crypto.mceliece.McElieceParameters;
import org.bc.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bc.pqc.jcajce.spec.McEliecePublicKeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;

public class BCMcEliecePublicKey implements CipherParameters, PublicKey {
   private static final long serialVersionUID = 1L;
   private String oid;
   private int n;
   private int t;
   private GF2Matrix g;
   private McElieceParameters McElieceParams;

   public BCMcEliecePublicKey(String var1, int var2, int var3, GF2Matrix var4) {
      this.oid = var1;
      this.n = var2;
      this.t = var3;
      this.g = var4;
   }

   public BCMcEliecePublicKey(McEliecePublicKeySpec var1) {
      this(var1.getOIDString(), var1.getN(), var1.getT(), var1.getG());
   }

   public BCMcEliecePublicKey(McEliecePublicKeyParameters var1) {
      this(var1.getOIDString(), var1.getN(), var1.getT(), var1.getG());
      this.McElieceParams = var1.getParameters();
   }

   public String getAlgorithm() {
      return "McEliece";
   }

   public int getN() {
      return this.n;
   }

   public int getK() {
      return this.g.getNumRows();
   }

   public int getT() {
      return this.t;
   }

   public GF2Matrix getG() {
      return this.g;
   }

   public String toString() {
      String var1 = "McEliecePublicKey:\n";
      var1 = var1 + " length of the code         : " + this.n + "\n";
      var1 = var1 + " error correction capability: " + this.t + "\n";
      var1 = var1 + " generator matrix           : " + this.g.toString();
      return var1;
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof BCMcEliecePublicKey)) {
         return false;
      } else {
         BCMcEliecePublicKey var2 = (BCMcEliecePublicKey)var1;
         return this.n == var2.n && this.t == var2.t && this.g.equals(var2.g);
      }
   }

   public int hashCode() {
      return this.n + this.t + this.g.hashCode();
   }

   public String getOIDString() {
      return this.oid;
   }

   protected ASN1ObjectIdentifier getOID() {
      return new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.1");
   }

   protected ASN1Primitive getAlgParams() {
      return null;
   }

   public byte[] getEncoded() {
      McEliecePublicKey var1 = new McEliecePublicKey(new ASN1ObjectIdentifier(this.oid), this.n, this.t, this.g);
      AlgorithmIdentifier var2 = new AlgorithmIdentifier(this.getOID(), DERNull.INSTANCE);

      try {
         SubjectPublicKeyInfo var3 = new SubjectPublicKeyInfo(var2, var1);
         return var3.getEncoded();
      } catch (IOException var4) {
         return null;
      }
   }

   public String getFormat() {
      return null;
   }

   public McElieceParameters getMcElieceParameters() {
      return this.McElieceParams;
   }
}
