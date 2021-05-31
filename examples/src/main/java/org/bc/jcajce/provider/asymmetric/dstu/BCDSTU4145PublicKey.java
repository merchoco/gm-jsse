package org.bc.jcajce.provider.asymmetric.dstu;

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
import org.bc.asn1.ua.DSTU4145BinaryField;
import org.bc.asn1.ua.DSTU4145ECBinary;
import org.bc.asn1.ua.DSTU4145NamedCurves;
import org.bc.asn1.ua.DSTU4145Params;
import org.bc.asn1.ua.DSTU4145PointEncoder;
import org.bc.asn1.ua.UAObjectIdentifiers;
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
import org.bc.jce.interfaces.ECPointEncoder;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.jce.spec.ECNamedCurveParameterSpec;
import org.bc.jce.spec.ECNamedCurveSpec;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class BCDSTU4145PublicKey implements ECPublicKey, org.bc.jce.interfaces.ECPublicKey, ECPointEncoder {
   static final long serialVersionUID = 7026240464295649314L;
   private String algorithm = "DSTU4145";
   private boolean withCompression;
   private transient ECPoint q;
   private transient ECParameterSpec ecSpec;
   private transient DSTU4145Params dstuParams;

   public BCDSTU4145PublicKey(BCDSTU4145PublicKey var1) {
      this.q = var1.q;
      this.ecSpec = var1.ecSpec;
      this.withCompression = var1.withCompression;
      this.dstuParams = var1.dstuParams;
   }

   public BCDSTU4145PublicKey(ECPublicKeySpec var1) {
      this.ecSpec = var1.getParams();
      this.q = EC5Util.convertPoint(this.ecSpec, var1.getW(), false);
   }

   public BCDSTU4145PublicKey(org.bc.jce.spec.ECPublicKeySpec var1) {
      this.q = var1.getQ();
      if (var1.getParams() != null) {
         ECCurve var2 = var1.getParams().getCurve();
         EllipticCurve var3 = EC5Util.convertCurve(var2, var1.getParams().getSeed());
         this.ecSpec = EC5Util.convertSpec(var3, var1.getParams());
      } else {
         if (this.q.getCurve() == null) {
            org.bc.jce.spec.ECParameterSpec var4 = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
            this.q = var4.getCurve().createPoint(this.q.getX().toBigInteger(), this.q.getY().toBigInteger(), false);
         }

         this.ecSpec = null;
      }

   }

   public BCDSTU4145PublicKey(String var1, ECPublicKeyParameters var2, ECParameterSpec var3) {
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

   public BCDSTU4145PublicKey(String var1, ECPublicKeyParameters var2, org.bc.jce.spec.ECParameterSpec var3) {
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

   public BCDSTU4145PublicKey(String var1, ECPublicKeyParameters var2) {
      this.algorithm = var1;
      this.q = var2.getQ();
      this.ecSpec = null;
   }

   private ECParameterSpec createSpec(EllipticCurve var1, ECDomainParameters var2) {
      return new ECParameterSpec(var1, new java.security.spec.ECPoint(var2.getG().getX().toBigInteger(), var2.getG().getY().toBigInteger()), var2.getN(), var2.getH().intValue());
   }

   public BCDSTU4145PublicKey(ECPublicKey var1) {
      this.algorithm = var1.getAlgorithm();
      this.ecSpec = var1.getParams();
      this.q = EC5Util.convertPoint(this.ecSpec, var1.getW(), false);
   }

   BCDSTU4145PublicKey(SubjectPublicKeyInfo var1) {
      this.populateFromPubKeyInfo(var1);
   }

   private void reverseBytes(byte[] var1) {
      for(int var3 = 0; var3 < var1.length / 2; ++var3) {
         byte var2 = var1[var3];
         var1[var3] = var1[var1.length - 1 - var3];
         var1[var1.length - 1 - var3] = var2;
      }

   }

   private void populateFromPubKeyInfo(SubjectPublicKeyInfo var1) {
      if (!var1.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145be) && !var1.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le)) {
         X962Parameters var13 = new X962Parameters((ASN1Primitive)var1.getAlgorithm().getParameters());
         ECCurve var14;
         EllipticCurve var15;
         if (var13.isNamedCurve()) {
            ASN1ObjectIdentifier var16 = (ASN1ObjectIdentifier)var13.getParameters();
            X9ECParameters var20 = ECUtil.getNamedCurveByOid(var16);
            var14 = var20.getCurve();
            var15 = EC5Util.convertCurve(var14, var20.getSeed());
            this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(var16), var15, new java.security.spec.ECPoint(var20.getG().getX().toBigInteger(), var20.getG().getY().toBigInteger()), var20.getN(), var20.getH());
         } else if (var13.isImplicitlyCA()) {
            this.ecSpec = null;
            var14 = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa().getCurve();
         } else {
            X9ECParameters var18 = X9ECParameters.getInstance(var13.getParameters());
            var14 = var18.getCurve();
            var15 = EC5Util.convertCurve(var14, var18.getSeed());
            this.ecSpec = new ECParameterSpec(var15, new java.security.spec.ECPoint(var18.getG().getX().toBigInteger(), var18.getG().getY().toBigInteger()), var18.getN(), var18.getH().intValue());
         }

         DERBitString var21 = var1.getPublicKeyData();
         byte[] var22 = var21.getBytes();
         Object var25 = new DEROctetString(var22);
         if (var22[0] == 4 && var22[1] == var22.length - 2 && (var22[2] == 2 || var22[2] == 3)) {
            int var26 = (new X9IntegerConverter()).getByteLength(var14);
            if (var26 >= var22.length - 3) {
               try {
                  var25 = (ASN1OctetString)ASN1Primitive.fromByteArray(var22);
               } catch (IOException var11) {
                  throw new IllegalArgumentException("error recovering public key");
               }
            }
         }

         X9ECPoint var27 = new X9ECPoint(var14, (ASN1OctetString)var25);
         this.q = var27.getPoint();
      } else {
         DERBitString var2 = var1.getPublicKeyData();
         this.algorithm = "DSTU4145";

         ASN1OctetString var3;
         try {
            var3 = (ASN1OctetString)ASN1Primitive.fromByteArray(var2.getBytes());
         } catch (IOException var12) {
            throw new IllegalArgumentException("error recovering public key");
         }

         byte[] var4 = var3.getOctets();
         if (var1.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le)) {
            this.reverseBytes(var4);
         }

         this.dstuParams = DSTU4145Params.getInstance((ASN1Sequence)var1.getAlgorithm().getParameters());
         Object var5 = null;
         if (this.dstuParams.isNamedCurve()) {
            ASN1ObjectIdentifier var6 = this.dstuParams.getNamedCurve();
            ECDomainParameters var7 = DSTU4145NamedCurves.getByOID(var6);
            var5 = new ECNamedCurveParameterSpec(var6.getId(), var7.getCurve(), var7.getG(), var7.getN(), var7.getH(), var7.getSeed());
         } else {
            DSTU4145ECBinary var17 = this.dstuParams.getECBinary();
            byte[] var23 = var17.getB();
            if (var1.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le)) {
               this.reverseBytes(var23);
            }

            DSTU4145BinaryField var8 = var17.getField();
            ECCurve.F2m var9 = new ECCurve.F2m(var8.getM(), var8.getK1(), var8.getK2(), var8.getK3(), var17.getA(), new BigInteger(1, var23));
            byte[] var10 = var17.getG();
            if (var1.getAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le)) {
               this.reverseBytes(var10);
            }

            var5 = new org.bc.jce.spec.ECParameterSpec(var9, DSTU4145PointEncoder.decodePoint(var9, var10), var17.getN());
         }

         ECCurve var19 = ((org.bc.jce.spec.ECParameterSpec)var5).getCurve();
         EllipticCurve var24 = EC5Util.convertCurve(var19, ((org.bc.jce.spec.ECParameterSpec)var5).getSeed());
         this.q = DSTU4145PointEncoder.decodePoint(var19, var4);
         if (this.dstuParams.isNamedCurve()) {
            this.ecSpec = new ECNamedCurveSpec(this.dstuParams.getNamedCurve().getId(), var24, new java.security.spec.ECPoint(((org.bc.jce.spec.ECParameterSpec)var5).getG().getX().toBigInteger(), ((org.bc.jce.spec.ECParameterSpec)var5).getG().getY().toBigInteger()), ((org.bc.jce.spec.ECParameterSpec)var5).getN(), ((org.bc.jce.spec.ECParameterSpec)var5).getH());
         } else {
            this.ecSpec = new ECParameterSpec(var24, new java.security.spec.ECPoint(((org.bc.jce.spec.ECParameterSpec)var5).getG().getX().toBigInteger(), ((org.bc.jce.spec.ECParameterSpec)var5).getG().getY().toBigInteger()), ((org.bc.jce.spec.ECParameterSpec)var5).getN(), ((org.bc.jce.spec.ECParameterSpec)var5).getH().intValue());
         }
      }

   }

   public byte[] getSbox() {
      return this.dstuParams != null ? this.dstuParams.getDKE() : DSTU4145Params.getDefaultDKE();
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
      if (this.algorithm.equals("DSTU4145")) {
         Object var1;
         if (this.dstuParams != null) {
            var1 = this.dstuParams;
         } else if (this.ecSpec instanceof ECNamedCurveSpec) {
            var1 = new DSTU4145Params(new ASN1ObjectIdentifier(((ECNamedCurveSpec)this.ecSpec).getName()));
         } else {
            var3 = EC5Util.convertCurve(this.ecSpec.getCurve());
            var4 = new X9ECParameters(var3, EC5Util.convertPoint(var3, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long)this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed());
            var1 = new X962Parameters(var4);
         }

         byte[] var7 = DSTU4145PointEncoder.encodePoint(this.q);

         try {
            var2 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145be, (ASN1Encodable)var1), new DEROctetString(var7));
         } catch (IOException var5) {
            return null;
         }
      } else {
         X962Parameters var6;
         if (this.ecSpec instanceof ECNamedCurveSpec) {
            ASN1ObjectIdentifier var8 = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)this.ecSpec).getName());
            if (var8 == null) {
               var8 = new ASN1ObjectIdentifier(((ECNamedCurveSpec)this.ecSpec).getName());
            }

            var6 = new X962Parameters(var8);
         } else if (this.ecSpec == null) {
            var6 = new X962Parameters(DERNull.INSTANCE);
         } else {
            var3 = EC5Util.convertCurve(this.ecSpec.getCurve());
            var4 = new X9ECParameters(var3, EC5Util.convertPoint(var3, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long)this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed());
            var6 = new X962Parameters(var4);
         }

         var3 = this.engineGetQ().getCurve();
         ASN1OctetString var9 = (ASN1OctetString)(new X9ECPoint(var3.createPoint(this.getQ().getX().toBigInteger(), this.getQ().getY().toBigInteger(), this.withCompression))).toASN1Primitive();
         var2 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, var6), var9.getOctets());
      }

      return KeyUtil.getEncodedSubjectPublicKeyInfo(var2);
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
      if (!(var1 instanceof BCDSTU4145PublicKey)) {
         return false;
      } else {
         BCDSTU4145PublicKey var2 = (BCDSTU4145PublicKey)var1;
         return this.engineGetQ().equals(var2.engineGetQ()) && this.engineGetSpec().equals(var2.engineGetSpec());
      }
   }

   public int hashCode() {
      return this.engineGetQ().hashCode() ^ this.engineGetSpec().hashCode();
   }

   private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
      var1.defaultReadObject();
      byte[] var2 = (byte[])var1.readObject();
      this.populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(var2)));
   }

   private void writeObject(ObjectOutputStream var1) throws IOException {
      var1.defaultWriteObject();
      var1.writeObject(this.getEncoded());
   }
}
