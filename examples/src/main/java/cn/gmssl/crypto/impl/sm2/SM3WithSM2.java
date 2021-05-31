package cn.gmssl.crypto.impl.sm2;

import cn.gmssl.crypto.impl.SM3;
import cn.gmssl.jce.provider.GMConf;
import cn.gmssl.jce.skf.ICryptoProvider;
import cn.gmssl.jce.skf.SKF_PrivateKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.DERSequence;
import org.bc.jcajce.provider.asymmetric.ec.BCSignatureSpi;
import org.bc.jce.interfaces.ECPrivateKey;
import org.bc.jce.interfaces.ECPublicKey;
import org.bc.jce.spec.ECParameterSpec;
import org.bc.jce.spec.ECPublicKeySpec;
import org.bc.math.ec.ECPoint;

public class SM3WithSM2 extends BCSignatureSpi {
   private boolean skf = false;
   private SKF_PrivateKey skfPri = null;
   private ECPublicKey publicKey = null;
   public byte[] id = null;

   public SM3WithSM2() {
      super(new SM3(), new SM2Signer(), new StdDSAEncoder());
   }

   protected void engineSetParameter(AlgorithmParameterSpec var1) {
      if (!(var1 instanceof SM2ParameterSpec)) {
         throw new RuntimeException("SM3WithSM2 must use SM2ParameterSpec");
      } else {
         SM2ParameterSpec var2 = (SM2ParameterSpec)var1;
         PublicKey var3 = var2.getPublicKey();

         try {
            this.publicKey = SM2Util.toTsgECPublicKey(var3);
         } catch (Exception var5) {
            throw new RuntimeException("toTsgECPublicKey");
         }

         this.id = var2.getId();
      }
   }

   protected void engineInitSign(PrivateKey var1) throws InvalidKeyException {
      this.skf = var1 instanceof SKF_PrivateKey;
      if (GMConf.skfDebug) {
         System.out.println("engineInitSign skf=" + this.skf);
      }

      if (this.skf) {
         this.skfPri = (SKF_PrivateKey)var1;
      } else {
         super.engineInitSign(var1);
      }

      try {
         if (this.id == null) {
            this.id = "1234567812345678".getBytes();
         }

         if (this.publicKey == null) {
            ECPrivateKey var2 = (ECPrivateKey)var1;
            BigInteger var3 = var2.getD();
            ECParameterSpec var4 = var2.getParameters();
            ECPoint var5 = var4.getG();
            ECPoint var6 = var5.multiply(var3);
            ECPoint var7 = var4.getCurve().createPoint(var6.getX().toBigInteger(), var6.getY().toBigInteger(), false);
            ECPublicKeySpec var8 = new ECPublicKeySpec(var7, var4);
            KeyFactory var9 = KeyFactory.getInstance("SM2", "GMJCE");
            this.publicKey = (ECPublicKey)var9.generatePublic(var8);
         }

         SM2Util.Z(this.id, this.publicKey, this.digest);
      } catch (Exception var10) {
         throw new InvalidKeyException(var10);
      }
   }

   protected byte[] engineSign() throws SignatureException {
      if (GMConf.skfDebug) {
         System.out.println("engineSign skf=" + this.skf);
      }

      byte[] var1;
      if (this.skf) {
         var1 = new byte[this.digest.getDigestSize()];
         this.digest.doFinal(var1, 0);

         try {
            ICryptoProvider var2 = this.skfPri.getCryptoProvider();
            byte[] var3 = var2.doSign(var1, 0, var1.length);
            byte[] var4 = new byte[32];
            byte[] var5 = new byte[32];
            System.arraycopy(var3, 0, var4, 0, 32);
            System.arraycopy(var3, 32, var5, 0, 32);
            BigInteger[] var6 = new BigInteger[]{new BigInteger(1, var4), new BigInteger(1, var5)};
            ASN1Integer[] var7 = new ASN1Integer[]{new ASN1Integer(var6[0]), new ASN1Integer(var6[1])};
            byte[] var8 = (new DERSequence(var7)).getEncoded("DER");
            if (GMConf.skfDebug) {
               System.out.println("SKF: rs.len=" + var8.length + "," + var8[0] + "," + var8[1]);
            }

            var8 = this.encoder.encode(var6[0], var6[1]);
            if (GMConf.skfDebug) {
               System.out.println("SKF: rs2.len=" + var8.length + "," + var8[0] + "," + var8[1]);
            }

            return var8;
         } catch (Exception var9) {
            throw new SignatureException(var9);
         }
      } else {
         var1 = super.engineSign();
         return var1;
      }
   }

   protected void engineInitVerify(PublicKey var1) throws InvalidKeyException {
      super.engineInitVerify(var1);

      try {
         this.publicKey = SM2Util.toTsgECPublicKey(var1);
      } catch (Exception var3) {
         throw new RuntimeException("toTsgECPublicKey");
      }

      if (this.id == null) {
         this.id = "1234567812345678".getBytes();
      }

      SM2Util.Z(this.id, this.publicKey, this.digest);
   }
}
