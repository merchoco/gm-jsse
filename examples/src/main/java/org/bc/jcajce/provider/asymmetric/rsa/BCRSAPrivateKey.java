package org.bc.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Enumeration;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERNull;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.jcajce.provider.asymmetric.util.KeyUtil;
import org.bc.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bc.jce.interfaces.PKCS12BagAttributeCarrier;

public class BCRSAPrivateKey implements RSAPrivateKey, PKCS12BagAttributeCarrier {
   static final long serialVersionUID = 5110188922551353628L;
   private static BigInteger ZERO = BigInteger.valueOf(0L);
   protected BigInteger modulus;
   protected BigInteger privateExponent;
   private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

   protected BCRSAPrivateKey() {
   }

   BCRSAPrivateKey(RSAKeyParameters var1) {
      this.modulus = var1.getModulus();
      this.privateExponent = var1.getExponent();
   }

   BCRSAPrivateKey(RSAPrivateKeySpec var1) {
      this.modulus = var1.getModulus();
      this.privateExponent = var1.getPrivateExponent();
   }

   BCRSAPrivateKey(RSAPrivateKey var1) {
      this.modulus = var1.getModulus();
      this.privateExponent = var1.getPrivateExponent();
   }

   public BigInteger getModulus() {
      return this.modulus;
   }

   public BigInteger getPrivateExponent() {
      return this.privateExponent;
   }

   public String getAlgorithm() {
      return "RSA";
   }

   public String getFormat() {
      return "PKCS#8";
   }

   public byte[] getEncoded() {
      return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new org.bc.asn1.pkcs.RSAPrivateKey(this.getModulus(), ZERO, this.getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
   }

   public boolean equals(Object var1) {
      if (!(var1 instanceof RSAPrivateKey)) {
         return false;
      } else if (var1 == this) {
         return true;
      } else {
         RSAPrivateKey var2 = (RSAPrivateKey)var1;
         return this.getModulus().equals(var2.getModulus()) && this.getPrivateExponent().equals(var2.getPrivateExponent());
      }
   }

   public int hashCode() {
      return this.getModulus().hashCode() ^ this.getPrivateExponent().hashCode();
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

   private void readObject(ObjectInputStream var1) throws IOException, ClassNotFoundException {
      var1.defaultReadObject();
      this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
   }

   private void writeObject(ObjectOutputStream var1) throws IOException {
      var1.defaultWriteObject();
   }
}
