package org.bc.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PrivateKey;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERNull;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.crypto.CipherParameters;
import org.bc.pqc.asn1.McElieceCCA2PrivateKey;
import org.bc.pqc.crypto.mceliece.McElieceCCA2Parameters;
import org.bc.pqc.crypto.mceliece.McElieceCCA2PrivateKeyParameters;
import org.bc.pqc.jcajce.spec.McElieceCCA2PrivateKeySpec;
import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;

public class BCMcElieceCCA2PrivateKey implements CipherParameters, PrivateKey {
   private static final long serialVersionUID = 1L;
   private String oid;
   private int n;
   private int k;
   private GF2mField field;
   private PolynomialGF2mSmallM goppaPoly;
   private Permutation p;
   private GF2Matrix h;
   private PolynomialGF2mSmallM[] qInv;
   private McElieceCCA2Parameters mcElieceCCA2Params;

   public BCMcElieceCCA2PrivateKey(String var1, int var2, int var3, GF2mField var4, PolynomialGF2mSmallM var5, Permutation var6, GF2Matrix var7, PolynomialGF2mSmallM[] var8) {
      this.oid = var1;
      this.n = var2;
      this.k = var3;
      this.field = var4;
      this.goppaPoly = var5;
      this.p = var6;
      this.h = var7;
      this.qInv = var8;
   }

   public BCMcElieceCCA2PrivateKey(McElieceCCA2PrivateKeySpec var1) {
      this(var1.getOIDString(), var1.getN(), var1.getK(), var1.getField(), var1.getGoppaPoly(), var1.getP(), var1.getH(), var1.getQInv());
   }

   public BCMcElieceCCA2PrivateKey(McElieceCCA2PrivateKeyParameters var1) {
      this(var1.getOIDString(), var1.getN(), var1.getK(), var1.getField(), var1.getGoppaPoly(), var1.getP(), var1.getH(), var1.getQInv());
      this.mcElieceCCA2Params = var1.getParameters();
   }

   public String getAlgorithm() {
      return "McEliece";
   }

   public int getN() {
      return this.n;
   }

   public int getK() {
      return this.k;
   }

   public int getT() {
      return this.goppaPoly.getDegree();
   }

   public GF2mField getField() {
      return this.field;
   }

   public PolynomialGF2mSmallM getGoppaPoly() {
      return this.goppaPoly;
   }

   public Permutation getP() {
      return this.p;
   }

   public GF2Matrix getH() {
      return this.h;
   }

   public PolynomialGF2mSmallM[] getQInv() {
      return this.qInv;
   }

   public String toString() {
      String var1 = "";
      var1 = var1 + " extension degree of the field      : " + this.n + "\n";
      var1 = var1 + " dimension of the code              : " + this.k + "\n";
      var1 = var1 + " irreducible Goppa polynomial       : " + this.goppaPoly + "\n";
      return var1;
   }

   public boolean equals(Object var1) {
      if (var1 != null && var1 instanceof BCMcElieceCCA2PrivateKey) {
         BCMcElieceCCA2PrivateKey var2 = (BCMcElieceCCA2PrivateKey)var1;
         return this.n == var2.n && this.k == var2.k && this.field.equals(var2.field) && this.goppaPoly.equals(var2.goppaPoly) && this.p.equals(var2.p) && this.h.equals(var2.h);
      } else {
         return false;
      }
   }

   public int hashCode() {
      return this.k + this.n + this.field.hashCode() + this.goppaPoly.hashCode() + this.p.hashCode() + this.h.hashCode();
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
      McElieceCCA2PrivateKey var1 = new McElieceCCA2PrivateKey(new ASN1ObjectIdentifier(this.oid), this.n, this.k, this.field, this.goppaPoly, this.p, this.h, this.qInv);

      PrivateKeyInfo var2;
      try {
         AlgorithmIdentifier var3 = new AlgorithmIdentifier(this.getOID(), DERNull.INSTANCE);
         var2 = new PrivateKeyInfo(var3, var1);
      } catch (IOException var5) {
         var5.printStackTrace();
         return null;
      }

      try {
         byte[] var6 = var2.getEncoded();
         return var6;
      } catch (IOException var4) {
         var4.printStackTrace();
         return null;
      }
   }

   public String getFormat() {
      return null;
   }

   public McElieceCCA2Parameters getMcElieceCCA2Parameters() {
      return this.mcElieceCCA2Params;
   }
}
