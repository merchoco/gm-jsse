package org.bc.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PublicKey;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERNull;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.CipherParameters;
import org.bc.pqc.asn1.McElieceCCA2PublicKey;
import org.bc.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.bc.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bc.pqc.jcajce.spec.McElieceCCA2PublicKeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;

public class BCMcElieceCCA2PublicKey implements CipherParameters, PublicKey {
   private static final long serialVersionUID = 1L;
   private String oid;
   private int n;
   private int t;
   private GF2Matrix g;
   private McElieceCCA2Parameters McElieceCCA2Params;

   public BCMcElieceCCA2PublicKey(String var1, int var2, int var3, GF2Matrix var4) {
      this.oid = var1;
      this.n = var2;
      this.t = var3;
      this.g = var4;
   }

   public BCMcElieceCCA2PublicKey(McElieceCCA2PublicKeySpec var1) {
      this(var1.getOIDString(), var1.getN(), var1.getT(), var1.getMatrixG());
   }

   public BCMcElieceCCA2PublicKey(McElieceCCA2PublicKeyParameters var1) {
      this(var1.getOIDString(), var1.getN(), var1.getT(), var1.getMatrixG());
      this.McElieceCCA2Params = var1.getParameters();
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
      if (var1 != null && var1 instanceof BCMcElieceCCA2PublicKey) {
         BCMcElieceCCA2PublicKey var2 = (BCMcElieceCCA2PublicKey)var1;
         return this.n == var2.n && this.t == var2.t && this.g.equals(var2.g);
      } else {
         return false;
      }
   }

   public int hashCode() {
      return this.n + this.t + this.g.hashCode();
   }

   public String getOIDString() {
      return this.oid;
   }

   protected ASN1ObjectIdentifier getOID() {
      return new ASN1ObjectIdentifier("1.3.6.1.4.1.8301.3.1.3.4.2");
   }

   protected ASN1Primitive getAlgParams() {
      return null;
   }

   public byte[] getEncoded() {
      McElieceCCA2PublicKey var1 = new McElieceCCA2PublicKey(new ASN1ObjectIdentifier(this.oid), this.n, this.t, this.g);
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

   public McElieceCCA2Parameters getMcElieceCCA2Parameters() {
      return this.McElieceCCA2Params;
   }
}
