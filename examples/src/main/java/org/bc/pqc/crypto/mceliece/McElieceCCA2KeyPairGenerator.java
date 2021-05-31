package org.bc.pqc.crypto.mceliece;

import java.security.SecureRandom;
import org.bc.crypto.AsymmetricCipherKeyPair;
import org.bc.crypto.AsymmetricCipherKeyPairGenerator;
import org.bc.crypto.KeyGenerationParameters;
import org.bc.pqc.math.linearalgebra.GF2Matrix;
import org.bc.pqc.math.linearalgebra.GF2mField;
import org.bc.pqc.math.linearalgebra.GoppaCode;
import org.bc.pqc.math.linearalgebra.Permutation;
import org.bc.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bc.pqc.math.linearalgebra.PolynomialRingGF2m;

public class McElieceCCA2KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
   public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2";
   private McElieceCCA2KeyGenerationParameters mcElieceCCA2Params;
   private int m;
   private int n;
   private int t;
   private int fieldPoly;
   private SecureRandom random;
   private boolean initialized = false;

   private void initializeDefault() {
      McElieceCCA2KeyGenerationParameters var1 = new McElieceCCA2KeyGenerationParameters(new SecureRandom(), new McElieceCCA2Parameters());
      this.init(var1);
   }

   public void init(KeyGenerationParameters var1) {
      this.mcElieceCCA2Params = (McElieceCCA2KeyGenerationParameters)var1;
      this.random = new SecureRandom();
      this.m = this.mcElieceCCA2Params.getParameters().getM();
      this.n = this.mcElieceCCA2Params.getParameters().getN();
      this.t = this.mcElieceCCA2Params.getParameters().getT();
      this.fieldPoly = this.mcElieceCCA2Params.getParameters().getFieldPoly();
      this.initialized = true;
   }

   public AsymmetricCipherKeyPair generateKeyPair() {
      if (!this.initialized) {
         this.initializeDefault();
      }

      GF2mField var1 = new GF2mField(this.m, this.fieldPoly);
      PolynomialGF2mSmallM var2 = new PolynomialGF2mSmallM(var1, this.t, 'I', this.random);
      PolynomialRingGF2m var3 = new PolynomialRingGF2m(var1, var2);
      PolynomialGF2mSmallM[] var4 = var3.getSquareRootMatrix();
      GF2Matrix var5 = GoppaCode.createCanonicalCheckMatrix(var1, var2);
      GoppaCode.MaMaPe var6 = GoppaCode.computeSystematicForm(var5, this.random);
      GF2Matrix var7 = var6.getSecondMatrix();
      Permutation var8 = var6.getPermutation();
      GF2Matrix var9 = (GF2Matrix)var7.computeTranspose();
      int var10 = var9.getNumRows();
      McElieceCCA2PublicKeyParameters var11 = new McElieceCCA2PublicKeyParameters("1.3.6.1.4.1.8301.3.1.3.4.2", this.n, this.t, var9, this.mcElieceCCA2Params.getParameters());
      McElieceCCA2PrivateKeyParameters var12 = new McElieceCCA2PrivateKeyParameters("1.3.6.1.4.1.8301.3.1.3.4.2", this.n, var10, var1, var2, var8, var5, var4, this.mcElieceCCA2Params.getParameters());
      return new AsymmetricCipherKeyPair(var11, var12);
   }
}
