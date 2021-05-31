package org.bc.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.Enumeration;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.DERBitString;
import org.bc.asn1.DERInteger;
import org.bc.asn1.DERNull;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bc.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.asn1.x9.X962Parameters;
import org.bc.asn1.x9.X9ECParameters;
import org.bc.asn1.x9.X9ObjectIdentifiers;
import org.bc.crypto.params.ECDomainParameters;
import org.bc.crypto.params.ECPrivateKeyParameters;
import org.bc.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bc.jcajce.provider.config.ProviderConfiguration;
import org.bc.jce.interfaces.ECPointEncoder;
import org.bc.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bc.jce.provider.BouncyCastleProvider;
import org.bc.jce.spec.ECNamedCurveSpec;
import org.bc.jce.spec.ECPrivateKeySpec;
import org.bc.math.ec.ECCurve;

public class BCECPrivateKey implements ECPrivateKey, org.bc.jce.interfaces.ECPrivateKey, PKCS12BagAttributeCarrier, ECPointEncoder {
   static final long serialVersionUID = 994553197664784084L;
   private String algorithm = "EC";
   private boolean withCompression;
   private transient BigInteger d;
   private transient ECParameterSpec ecSpec;
   private transient ProviderConfiguration configuration;
   private transient DERBitString publicKey;
   private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

   protected BCECPrivateKey() {
   }

   public BCECPrivateKey(ECPrivateKey var1, ProviderConfiguration var2) {
      this.d = var1.getS();
      this.algorithm = var1.getAlgorithm();
      this.ecSpec = var1.getParams();
      this.configuration = var2;
   }

   public BCECPrivateKey(String var1, ECPrivateKeySpec var2, ProviderConfiguration var3) {
      this.algorithm = var1;
      this.d = var2.getD();
      if (var2.getParams() != null) {
         ECCurve var4 = var2.getParams().getCurve();
         EllipticCurve var5 = EC5Util.convertCurve(var4, var2.getParams().getSeed());
         this.ecSpec = EC5Util.convertSpec(var5, var2.getParams());
      } else {
         this.ecSpec = null;
      }

      this.configuration = var3;
   }

   public BCECPrivateKey(String var1, java.security.spec.ECPrivateKeySpec var2, ProviderConfiguration var3) {
      this.algorithm = var1;
      this.d = var2.getS();
      this.ecSpec = var2.getParams();
      this.configuration = var3;
   }

   public BCECPrivateKey(String var1, BCECPrivateKey var2) {
      this.algorithm = var1;
      this.d = var2.d;
      this.ecSpec = var2.ecSpec;
      this.withCompression = var2.withCompression;
      this.attrCarrier = var2.attrCarrier;
      this.publicKey = var2.publicKey;
      this.configuration = var2.configuration;
   }

   public BCECPrivateKey(String var1, ECPrivateKeyParameters var2, BCECPublicKey var3, ECParameterSpec var4, ProviderConfiguration var5) {
      ECDomainParameters var6 = var2.getParameters();
      this.algorithm = var1;
      this.d = var2.getD();
      this.configuration = var5;
      if (var4 == null) {
         EllipticCurve var7 = EC5Util.convertCurve(var6.getCurve(), var6.getSeed());
         this.ecSpec = new ECParameterSpec(var7, new ECPoint(var6.getG().getX().toBigInteger(), var6.getG().getY().toBigInteger()), var6.getN(), var6.getH().intValue());
      } else {
         this.ecSpec = var4;
      }

      this.publicKey = this.getPublicKeyDetails(var3);
   }

   public BCECPrivateKey(String var1, ECPrivateKeyParameters var2, BCECPublicKey var3, org.bc.jce.spec.ECParameterSpec var4, ProviderConfiguration var5) {
      ECDomainParameters var6 = var2.getParameters();
      this.algorithm = var1;
      this.d = var2.getD();
      this.configuration = var5;
      EllipticCurve var7;
      if (var4 == null) {
         var7 = EC5Util.convertCurve(var6.getCurve(), var6.getSeed());
         this.ecSpec = new ECParameterSpec(var7, new ECPoint(var6.getG().getX().toBigInteger(), var6.getG().getY().toBigInteger()), var6.getN(), var6.getH().intValue());
      } else {
         var7 = EC5Util.convertCurve(var4.getCurve(), var4.getSeed());
         this.ecSpec = new ECParameterSpec(var7, new ECPoint(var4.getG().getX().toBigInteger(), var4.getG().getY().toBigInteger()), var4.getN(), var4.getH().intValue());
      }

      this.publicKey = this.getPublicKeyDetails(var3);
   }

   public BCECPrivateKey(String var1, ECPrivateKeyParameters var2, ProviderConfiguration var3) {
      this.algorithm = var1;
      this.d = var2.getD();
      this.ecSpec = null;
      this.configuration = var3;
   }

   BCECPrivateKey(String var1, PrivateKeyInfo var2, ProviderConfiguration var3) throws IOException {
      this.algorithm = var1;
      this.configuration = var3;
      this.populateFromPrivKeyInfo(var2);
   }

   private void populateFromPrivKeyInfo(PrivateKeyInfo var1) throws IOException {
      X962Parameters var2 = X962Parameters.getInstance(var1.getPrivateKeyAlgorithm().getParameters());
      if (var2.isNamedCurve()) {
         ASN1ObjectIdentifier var3 = ASN1ObjectIdentifier.getInstance(var2.getParameters());
         X9ECParameters var4 = ECUtil.getNamedCurveByOid(var3);
         if (var4 == null) {
            ECDomainParameters var5 = ECGOST3410NamedCurves.getByOID(var3);
            EllipticCurve var6 = EC5Util.convertCurve(var5.getCurve(), var5.getSeed());
            this.ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(var3), var6, new ECPoint(var5.getG().getX().toBigInteger(), var5.getG().getY().toBigInteger()), var5.getN(), var5.getH());
         } else {
            EllipticCurve var12 = EC5Util.convertCurve(var4.getCurve(), var4.getSeed());
            this.ecSpec = new ECNamedCurveSpec(ECUtil.getCurveName(var3), var12, new ECPoint(var4.getG().getX().toBigInteger(), var4.getG().getY().toBigInteger()), var4.getN(), var4.getH());
         }
      } else if (var2.isImplicitlyCA()) {
         this.ecSpec = null;
      } else {
         X9ECParameters var7 = X9ECParameters.getInstance(var2.getParameters());
         EllipticCurve var9 = EC5Util.convertCurve(var7.getCurve(), var7.getSeed());
         this.ecSpec = new ECParameterSpec(var9, new ECPoint(var7.getG().getX().toBigInteger(), var7.getG().getY().toBigInteger()), var7.getN(), var7.getH().intValue());
      }

      ASN1Encodable var8 = var1.parsePrivateKey();
      if (var8 instanceof DERInteger) {
         ASN1Integer var10 = DERInteger.getInstance(var8);
         this.d = var10.getValue();
      } else {
         org.bc.asn1.sec.ECPrivateKey var11 = org.bc.asn1.sec.ECPrivateKey.getInstance(var8);
         this.d = var11.getKey();
         this.publicKey = var11.getPublicKey();
      }

   }

   public String getAlgorithm() {
      return this.algorithm;
   }

   public String getFormat() {
      return "PKCS#8";
   }

   public byte[] getEncoded() {
      X962Parameters var1;
      if (this.ecSpec instanceof ECNamedCurveSpec) {
         Object var2 = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)this.ecSpec).getName());
         if (var2 == null) {
            var2 = new DERObjectIdentifier(((ECNamedCurveSpec)this.ecSpec).getName());
         }

         var1 = new X962Parameters((ASN1Primitive)var2);
      } else if (this.ecSpec == null) {
         var1 = new X962Parameters(DERNull.INSTANCE);
      } else {
         ECCurve var6 = EC5Util.convertCurve(this.ecSpec.getCurve());
         X9ECParameters var3 = new X9ECParameters(var6, EC5Util.convertPoint(var6, this.ecSpec.getGenerator(), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf((long)this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed());
         var1 = new X962Parameters(var3);
      }

      org.bc.asn1.sec.ECPrivateKey var7;
      if (this.publicKey != null) {
         var7 = new org.bc.asn1.sec.ECPrivateKey(this.getS(), this.publicKey, var1);
      } else {
         var7 = new org.bc.asn1.sec.ECPrivateKey(this.getS(), var1);
      }

      try {
         PrivateKeyInfo var8;
         if (this.algorithm.equals("ECGOST3410")) {
            var8 = new PrivateKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, var1.toASN1Primitive()), var7.toASN1Primitive());
         } else {
            var8 = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, var1.toASN1Primitive()), var7.toASN1Primitive());
         }

         return var8.getEncoded("DER");
      } catch (IOException var5) {
         return null;
      }
   }

   public ECParameterSpec getParams() {
      return this.ecSpec;
   }

   public org.bc.jce.spec.ECParameterSpec getParameters() {
      return this.ecSpec == null ? null : EC5Util.convertSpec(this.ecSpec, this.withCompression);
   }

   org.bc.jce.spec.ECParameterSpec engineGetSpec() {
      return this.ecSpec != null ? EC5Util.convertSpec(this.ecSpec, this.withCompression) : this.configuration.getEcImplicitlyCa();
   }

   public BigInteger getS() {
      return this.d;
   }

   public BigInteger getD() {
      return this.d;
   }

   public void setBagAttribute(ASN1ObjectIdentifier var1, ASN1Encodable var2) {
      this.attrCarrier.setBagAttribute(var1, var2);
   }

   public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier var1) {
      return this.attrCarrier.getBagAttribute(var1);
   }

   public Enumeration getBagAttributeKeys() {
      return this.attrCarrier.getBagAttributeKeys();
   }

   public void setPointFormat(String var1) {
      this.withCompression = !"UNCOMPRESSED".equalsIgnoreCase(var1);
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof BCECPrivateKey)) {
         return false;
      } else {
         BCECPrivateKey var2 = (BCECPrivateKey)var1;
         return this.getD().equals(var2.getD()) && this.engineGetSpec().equals(var2.engineGetSpec());
      }
   }

   public int hashCode() {
      return this.getD().hashCode() ^ this.engineGetSpec().hashCode();
   }

   public String toString() {
      StringBuffer var1 = new StringBuffer();
      String var2 = System.getProperty("line.separator");
      var1.append("EC Private Key").append(var2);
      var1.append("             S: ").append(this.d.toString(16)).append(var2);
      return var1.toString();
   }

   private DERBitString getPublicKeyDetails(BCECPublicKey var1) {
      try {
         SubjectPublicKeyInfo var2 = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(var1.getEncoded()));
         return var2.getPublicKeyData();
      } catch (IOException var3) {
         return null;
      }
   }

   private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
      var1.defaultReadObject();
      byte[] var2 = (byte[])var1.readObject();
      this.populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(var2)));
      this.configuration = BouncyCastleProvider.CONFIGURATION;
      this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
   }

   private void writeObject(ObjectOutputStream var1) throws IOException {
      var1.defaultWriteObject();
      var1.writeObject(this.getEncoded());
   }
}
