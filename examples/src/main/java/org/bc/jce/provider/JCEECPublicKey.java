package org.bc.jce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERNull;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bc.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bc.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x9.X962Parameters;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.asn1.x9.X9ECPoint;
import org.bc.asn1.x9.X9IntegerConverter;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.jcajce.provider.asymmetric.ec.EC5Util;
import org.bc.jcajce.provider.asymmetric.ec.ECUtil;
import org.bc.jcajce.provider.asymmetric.util.KeyUtil;
import org.bc.jce.ECGOST3410NamedCurveTable;
import org.bc.jce.interfaces.ECPointEncoder;
import org.bc.jce.spec.ECNamedCurveParameterSpec;
import org.bc.jce.spec.ECNamedCurveSpec;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class JCEECPublicKey implements ECPublicKey, org.bc.jce.interfaces.ECPublicKey, ECPointEncoder {
   private String algorithm = "EC";
   private ECPoint q;
   private ECParameterSpec ecSpec;
   private boolean withCompression;
   private GOST3410PublicKeyAlgParameters gostParams;

   public JCEECPublicKey(String var1, JCEECPublicKey var2) {
      this.algorithm = var1;
      this.q = var2.q;
      this.ecSpec = var2.ecSpec;
      this.withCompression = var2.withCompression;
      this.gostParams = var2.gostParams;
   }

   public JCEECPublicKey(String var1, ECPublicKeySpec var2) {
      this.algorithm = var1;
      this.ecSpec = var2.getParams();
      this.q = EC5Util.convertPoint(this.ecSpec, var2.getW(), false);
   }

   public JCEECPublicKey(String var1, org.bc.jce.spec.ECPublicKeySpec var2) {
      this.algorithm = var1;
      this.q = var2.getQ();
      if (var2.getParams() != null) {
         ECCurve var3 = var2.getParams().getCurve();
         EllipticCurve var4 = EC5Util.convertCurve(var3, var2.getParams().getSeed());
         this.ecSpec = EC5Util.convertSpec(var4, var2.getParams());
      } else {
         if (this.q.getCurve() == null) {
            org.bc.jce.spec.ECParameterSpec var5 = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
            this.q = var5.getCurve().createPoint(this.q.getX().toBigInteger(), this.q.getY().toBigInteger(), false);
         }

         this.ecSpec = null;
      }

   }

   public JCEECPublicKey(String var1, ECPublicKeyParameters var2, ECParameterSpec var3) {
      ECDomainParameters var4 = var2.getParameters();
      this.algorithm = var1;
      this.q = var2.getQ();
      if (var3 == null) {
         EllipticCurve var5 = EC5Util.convertCurve(var4.getCurve(), var4.getSeed());
         this.ecSpec = this.createSpec(var5, var4);
      } else {
         this.ecSpec = var3;
      }

   }

   public JCEECPublicKey(String var1, ECPublicKeyParameters var2, org.bc.jce.spec.ECParameterSpec var3) {
      ECDomainParameters var4 = var2.getParameters();
      this.algorithm = var1;
      this.q = var2.getQ();
      EllipticCurve var5;
      if (var3 == null) {
         var5 = EC5Util.convertCurve(var4.getCurve(), var4.getSeed());
         this.ecSpec = this.createSpec(var5, var4);
      } else {
         var5 = EC5Util.convertCurve(var3.getCurve(), var3.getSeed());
         this.ecSpec = EC5Util.convertSpec(var5, var3);
      }

   }

   public JCEECPublicKey(String var1, ECPublicKeyParameters var2) {
      this.algorithm = var1;
      this.q = var2.getQ();
      this.ecSpec = null;
   }

   private ECParameterSpec createSpec(EllipticCurve var1, ECDomainParameters var2) {
      return new ECParameterSpec(var1, new java.security.spec.ECPoint(var2.getG().getX().toBigInteger(), var2.getG().getY().toBigInteger()), var2.getN(), var2.getH().intValue());
   }

   public JCEECPublicKey(ECPublicKey var1) {
      this.algorithm = var1.getAlgorithm();
      this.ecSpec = var1.getParams();
      this.q = EC5Util.convertPoint(this.ecSpec, var1.getW(), false);
   }

   JCEECPublicKey(SubjectPublicKeyInfo var1) {
      this.populateFromPubKeyInfo(var1);
   }

   private void populateFromPubKeyInfo(SubjectPublicKeyInfo var1) {
      byte[] var6;
      if (var1.getAlgorithmId().getObjectId().equals(CryptoProObjectIdentifiers.gostR3410_2001)) {
         DERBitString var2 = var1.getPublicKeyData();
         this.algorithm = "ECGOST3410";

         ASN1OctetString var3;
         try {
            var3 = (ASN1OctetString)ASN1Primitive.fromByteArray(var2.getBytes());
         } catch (IOException var11) {
            throw new IllegalArgumentException("error recovering public key");
         }

         byte[] var4 = var3.getOctets();
         byte[] var5 = new byte[32];
         var6 = new byte[32];

         int var7;
         for(var7 = 0; var7 != var5.length; ++var7) {
            var5[var7] = var4[31 - var7];
         }

         for(var7 = 0; var7 != var6.length; ++var7) {
            var6[var7] = var4[63 - var7];
         }

         this.gostParams = new GOST3410PublicKeyAlgParameters((ASN1Sequence)var1.getAlgorithmId().getParameters());
         ECNamedCurveParameterSpec var20 = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(this.gostParams.getPublicKeyParamSet()));
         ECCurve var8 = var20.getCurve();
         EllipticCurve var9 = EC5Util.convertCurve(var8, var20.getSeed());
         this.q = var8.createPoint(new BigInteger(1, var5), new BigInteger(1, var6), false);
         this.ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(this.gostParams.getPublicKeyParamSet()), var9, new java.security.spec.ECPoint(var20.getG().getX().toBigInteger(), var20.getG().getY().toBigInteger()), var20.getN(), var20.getH());
      } else {
         X962Parameters var12 = new X962Parameters((ASN1Primitive)var1.getAlgorithmId().getParameters());
         ECCurve var13;
         EllipticCurve var14;
         if (var12.isNamedCurve()) {
            ASN1ObjectIdentifier var15 = (ASN1ObjectIdentifier)var12.getParameters();
            X9ECParameters var18 = ECUtil.getNamedCurveByOid(var15);
            var13 = var18.getCurve();
            var14 = EC5Util.convertCurve(var13, var18.getSeed());
            this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(var15), var14, new java.security.spec.ECPoint(var18.getG().getX().toBigInteger(), var18.getG().getY().toBigInteger()), var18.getN(), var18.getH());
         } else if (var12.isImplicitlyCA()) {
            this.ecSpec = null;
            var13 = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getCurve();
         } else {
            X9ECParameters var16 = X9ECParameters.getInstance(var12.getParameters());
            var13 = var16.getCurve();
            var14 = EC5Util.convertCurve(var13, var16.getSeed());
            this.ecSpec = new ECParameterSpec(var14, new java.security.spec.ECPoint(var16.getG().getX().toBigInteger(), var16.getG().getY().toBigInteger()), var16.getN(), var16.getH().intValue());
         }

         DERBitString var17 = var1.getPublicKeyData();
         var6 = var17.getBytes();
         Object var21 = new DEROctetString(var6);
         if (var6[0] == 4 && var6[1] == var6.length - 2 && (var6[2] == 2 || var6[2] == 3)) {
            int var19 = (new X9IntegerConverter()).getByteLength(var13);
            if (var19 >= var6.length - 3) {
               try {
                  var21 = (ASN1OctetString)ASN1Primitive.fromByteArray(var6);
               } catch (IOException var10) {
                  throw new IllegalArgumentException("error recovering public key");
               }
            }
         }

         X9ECPoint var22 = new X9ECPoint(var13, (ASN1OctetString)var21);
         this.q = var22.getPoint();
      }

   }

   public String getAlgorithm() {
      return this.algorithm;
   }

   public String getFormat() {
      return "X.509";
   }

   public byte[] getEncoded() {
      SubjectPublicKeyInfo var2;
      ECCurve var3;
      X9ECParameters var4;
      if (this.algorithm.equals("ECGOST3410")) {
         Object var1;
         if (this.gostParams != null) {
            var1 = this.gostParams;
         } else if (this.ecSpec instanceof ECNamedCurveSpec) {
            var1 = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)this.ecSpec).getName()), CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
         } else {
            var3 = EC5Util.convertCurve(this.ecSpec.getCurve());
            var4 = new X9ECParameters(var3, EC5Util.convertPoint(var3, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long)this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed());
            var1 = new X962Parameters(var4);
         }

         BigInteger var9 = this.q.getX().toBigInteger();
         BigInteger var11 = this.q.getY().toBigInteger();
         byte[] var5 = new byte[64];
         this.extractBytes(var5, 0, var9);
         this.extractBytes(var5, 32, var11);

         try {
            var2 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, (ASN1Encodable)var1), new DEROctetString(var5));
         } catch (IOException var7) {
            return null;
         }
      } else {
         X962Parameters var8;
         if (this.ecSpec instanceof ECNamedCurveSpec) {
            ASN1ObjectIdentifier var10 = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)this.ecSpec).getName());
            if (var10 == null) {
               var10 = new ASN1ObjectIdentifier(((ECNamedCurveSpec)this.ecSpec).getName());
            }

            var8 = new X962Parameters(var10);
         } else if (this.ecSpec == null) {
            var8 = new X962Parameters(DERNull.INSTANCE);
         } else {
            var3 = EC5Util.convertCurve(this.ecSpec.getCurve());
            var4 = new X9ECParameters(var3, EC5Util.convertPoint(var3, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long)this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed());
            var8 = new X962Parameters(var4);
         }

         var3 = this.engineGetQ().getCurve();
         ASN1OctetString var12 = (ASN1OctetString)(new X9ECPoint(var3.createPoint(this.getQ().getX().toBigInteger(), this.getQ().getY().toBigInteger(), this.withCompression))).toASN1Primitive();
         var2 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, var8), var12.getOctets());
      }

      return KeyUtil.getEncodedSubjectPublicKeyInfo(var2);
   }

   private void extractBytes(byte[] var1, int var2, BigInteger var3) {
      byte[] var4 = var3.toByteArray();
      if (var4.length < 32) {
         byte[] var5 = new byte[32];
         System.arraycopy(var4, 0, var5, var5.length - var4.length, var4.length);
         var4 = var5;
      }

      for(int var6 = 0; var6 != 32; ++var6) {
         var1[var2 + var6] = var4[var4.length - 1 - var6];
      }

   }

   public ECParameterSpec getParams() {
      return this.ecSpec;
   }

   public org.bc.jce.spec.ECParameterSpec getParameters() {
      return this.ecSpec == null ? null : EC5Util.convertSpec(this.ecSpec, this.withCompression);
   }

   public java.security.spec.ECPoint getW() {
      return new java.security.spec.ECPoint(this.q.getX().toBigInteger(), this.q.getY().toBigInteger());
   }

   public ECPoint getQ() {
      if (this.ecSpec == null) {
         return (ECPoint)(this.q instanceof ECPoint.Fp ? new ECPoint.Fp((ECCurve)null, this.q.getX(), this.q.getY()) : new ECPoint.F2m((ECCurve)null, this.q.getX(), this.q.getY()));
      } else {
         return this.q;
      }
   }

   public ECPoint engineGetQ() {
      return this.q;
   }

   org.bc.jce.spec.ECParameterSpec engineGetSpec() {
      return this.ecSpec != null ? EC5Util.convertSpec(this.ecSpec, this.withCompression) : BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
   }

   public String toString() {
      StringBuffer var1 = new StringBuffer();
      String var2 = System.getProperty("line.separator");
      var1.append("EC Public Key").append(var2);
      var1.append("            X: ").append(this.q.getX().toBigInteger().toString(16)).append(var2);
      var1.append("            Y: ").append(this.q.getY().toBigInteger().toString(16)).append(var2);
      return var1.toString();
   }

   public void setPointFormat(String var1) {
      this.withCompression = !"UNCOMPRESSED".equalsIgnoreCase(var1);
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof JCEECPublicKey)) {
         return false;
      } else {
         JCEECPublicKey var2 = (JCEECPublicKey)var1;
         return this.engineGetQ().equals(var2.engineGetQ()) && this.engineGetSpec().equals(var2.engineGetSpec());
      }
   }

   public int hashCode() {
      return this.engineGetQ().hashCode() ^ this.engineGetSpec().hashCode();
   }

   private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
      byte[] var2 = (byte[])var1.readObject();
      this.populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(var2)));
      this.algorithm = (String)var1.readObject();
      this.withCompression = var1.readBoolean();
   }

   private void writeObject(ObjectOutputStream var1) throws IOException {
      var1.writeObject(this.getEncoded());
      var1.writeObject(this.algorithm);
      var1.writeBoolean(this.withCompression);
   }
}
