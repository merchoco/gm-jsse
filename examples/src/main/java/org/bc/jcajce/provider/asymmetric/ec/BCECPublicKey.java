package org.bc.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERNull;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x9.X962Parameters;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.asn1.x9.X9ECPoint;
import org.bc.asn1.x9.X9IntegerConverter;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPublicKeyParameters;
import org.bc.jcajce.provider.asymmetric.util.KeyUtil;
import org.bc.jcajce.provider.config.ProviderConfiguration;
import org.bc.jce.interfaces.ECPointEncoder;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.jce.spec.ECNamedCurveSpec;
import org.bc.math.ec.ECCurve;
import org.bc.math.ec.ECPoint;

public class BCECPublicKey implements ECPublicKey, org.bc.jce.interfaces.ECPublicKey, ECPointEncoder {
   static final long serialVersionUID = 2422789860422731812L;
   private String algorithm = "EC";
   private boolean withCompression;
   private transient ECPoint q;
   private transient ECParameterSpec ecSpec;
   private transient ProviderConfiguration configuration;

   public BCECPublicKey(String var1, BCECPublicKey var2) {
      this.algorithm = var1;
      this.q = var2.q;
      this.ecSpec = var2.ecSpec;
      this.withCompression = var2.withCompression;
      this.configuration = var2.configuration;
   }

   public BCECPublicKey(String var1, ECPublicKeySpec var2, ProviderConfiguration var3) {
      this.algorithm = var1;
      this.ecSpec = var2.getParams();
      this.q = EC5Util.convertPoint(this.ecSpec, var2.getW(), false);
      this.configuration = var3;
   }

   public BCECPublicKey(String var1, org.bc.jce.spec.ECPublicKeySpec var2, ProviderConfiguration var3) {
      this.algorithm = var1;
      this.q = var2.getQ();
      if (var2.getParams() != null) {
         ECCurve var4 = var2.getParams().getCurve();
         EllipticCurve var5 = EC5Util.convertCurve(var4, var2.getParams().getSeed());
         this.ecSpec = EC5Util.convertSpec(var5, var2.getParams());
      } else {
         if (this.q.getCurve() == null) {
            org.bc.jce.spec.ECParameterSpec var6 = var3.getEcImplicitlyCa();
            this.q = var6.getCurve().createPoint(this.q.getX().toBigInteger(), this.q.getY().toBigInteger(), false);
         }

         this.ecSpec = null;
      }

      this.configuration = var3;
   }

   public BCECPublicKey(String var1, ECPublicKeyParameters var2, ECParameterSpec var3, ProviderConfiguration var4) {
      ECDomainParameters var5 = var2.getParameters();
      this.algorithm = var1;
      this.q = var2.getQ();
      if (var3 == null) {
         EllipticCurve var6 = EC5Util.convertCurve(var5.getCurve(), var5.getSeed());
         this.ecSpec = this.createSpec(var6, var5);
      } else {
         this.ecSpec = var3;
      }

      this.configuration = var4;
   }

   public BCECPublicKey(String var1, ECPublicKeyParameters var2, org.bc.jce.spec.ECParameterSpec var3, ProviderConfiguration var4) {
      ECDomainParameters var5 = var2.getParameters();
      this.algorithm = var1;
      this.q = var2.getQ();
      EllipticCurve var6;
      if (var3 == null) {
         var6 = EC5Util.convertCurve(var5.getCurve(), var5.getSeed());
         this.ecSpec = this.createSpec(var6, var5);
      } else {
         var6 = EC5Util.convertCurve(var3.getCurve(), var3.getSeed());
         this.ecSpec = EC5Util.convertSpec(var6, var3);
      }

      this.configuration = var4;
   }

   public BCECPublicKey(String var1, ECPublicKeyParameters var2, ProviderConfiguration var3) {
      this.algorithm = var1;
      this.q = var2.getQ();
      this.ecSpec = null;
      this.configuration = var3;
   }

   public BCECPublicKey(ECPublicKey var1, ProviderConfiguration var2) {
      this.algorithm = var1.getAlgorithm();
      this.ecSpec = var1.getParams();
      this.q = EC5Util.convertPoint(this.ecSpec, var1.getW(), false);
   }

   BCECPublicKey(String var1, SubjectPublicKeyInfo var2, ProviderConfiguration var3) {
      this.algorithm = var1;
      this.configuration = var3;
      this.populateFromPubKeyInfo(var2);
   }

   private ECParameterSpec createSpec(EllipticCurve var1, ECDomainParameters var2) {
      return new ECParameterSpec(var1, new java.security.spec.ECPoint(var2.getG().getX().toBigInteger(), var2.getG().getY().toBigInteger()), var2.getN(), var2.getH().intValue());
   }

   private void populateFromPubKeyInfo(SubjectPublicKeyInfo var1) {
      X962Parameters var2 = new X962Parameters((ASN1Primitive)var1.getAlgorithm().getParameters());
      ECCurve var3;
      EllipticCurve var4;
      if (var2.isNamedCurve()) {
         ASN1ObjectIdentifier var5 = (ASN1ObjectIdentifier)var2.getParameters();
         X9ECParameters var6 = ECUtil.getNamedCurveByOid(var5);
         var3 = var6.getCurve();
         var4 = EC5Util.convertCurve(var3, var6.getSeed());
         this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(var5), var4, new java.security.spec.ECPoint(var6.getG().getX().toBigInteger(), var6.getG().getY().toBigInteger()), var6.getN(), var6.getH());
      } else if (var2.isImplicitlyCA()) {
         this.ecSpec = null;
         var3 = this.configuration.getEcImplicitlyCa().getCurve();
      } else {
         X9ECParameters var11 = X9ECParameters.getInstance(var2.getParameters());
         var3 = var11.getCurve();
         var4 = EC5Util.convertCurve(var3, var11.getSeed());
         this.ecSpec = new ECParameterSpec(var4, new java.security.spec.ECPoint(var11.getG().getX().toBigInteger(), var11.getG().getY().toBigInteger()), var11.getN(), var11.getH().intValue());
      }

      DERBitString var12 = var1.getPublicKeyData();
      byte[] var13 = var12.getBytes();
      Object var7 = new DEROctetString(var13);
      if (var13[0] == 4 && var13[1] == var13.length - 2 && (var13[2] == 2 || var13[2] == 3)) {
         int var8 = (new X9IntegerConverter()).getByteLength(var3);
         if (var8 >= var13.length - 3) {
            try {
               var7 = (ASN1OctetString)ASN1Primitive.fromByteArray(var13);
            } catch (IOException var10) {
               throw new IllegalArgumentException("error recovering public key");
            }
         }
      }

      X9ECPoint var14 = new X9ECPoint(var3, (ASN1OctetString)var7);
      this.q = var14.getPoint();
   }

   public String getAlgorithm() {
      return this.algorithm;
   }

   public String getFormat() {
      return "X.509";
   }

   public byte[] getEncoded() {
      X962Parameters var1;
      ECCurve var5;
      if (this.ecSpec instanceof ECNamedCurveSpec) {
         ASN1ObjectIdentifier var3 = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)this.ecSpec).getName());
         if (var3 == null) {
            var3 = new ASN1ObjectIdentifier(((ECNamedCurveSpec)this.ecSpec).getName());
         }

         var1 = new X962Parameters(var3);
      } else if (this.ecSpec == null) {
         var1 = new X962Parameters(DERNull.INSTANCE);
      } else {
         var5 = EC5Util.convertCurve(this.ecSpec.getCurve());
         X9ECParameters var4 = new X9ECParameters(var5, EC5Util.convertPoint(var5, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long)this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed());
         var1 = new X962Parameters(var4);
      }

      var5 = this.engineGetQ().getCurve();
      ASN1OctetString var6 = (ASN1OctetString)(new X9ECPoint(var5.createPoint(this.getQ().getX().toBigInteger(), this.getQ().getY().toBigInteger(), this.withCompression))).toASN1Primitive();
      SubjectPublicKeyInfo var2 = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, var1), var6.getOctets());
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
      return this.ecSpec != null ? EC5Util.convertSpec(this.ecSpec, this.withCompression) : this.configuration.getEcImplicitlyCa();
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
      if (!(var1 instanceof BCECPublicKey)) {
         return false;
      } else {
         BCECPublicKey var2 = (BCECPublicKey)var1;
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
      this.configuration = BouncyCastleProvider.CONFIGURATION;
   }

   private void writeObject(ObjectOutputStream var1) throws IOException {
      var1.defaultWriteObject();
      var1.writeObject(this.getEncoded());
   }
}
