package org.bc.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.bc.asn1.ASN1Encodable;
import org.bc.asn1.DERNull;
import org.bc.asn1.pkcs.PKCSObjectIdentifiers;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.crypto.params.RSAKeyParameters;
import org.bc.jcajce.provider.asymmetric.util.KeyUtil;

public class BCRSAPublicKey implements RSAPublicKey {
   static final long serialVersionUID = 2675817738516720772L;
   private BigInteger modulus;
   private BigInteger publicExponent;

   BCRSAPublicKey(RSAKeyParameters var1) {
      this.modulus = var1.getModulus();
      this.publicExponent = var1.getExponent();
   }

   BCRSAPublicKey(RSAPublicKeySpec var1) {
      this.modulus = var1.getModulus();
      this.publicExponent = var1.getPublicExponent();
   }

   BCRSAPublicKey(RSAPublicKey var1) {
      this.modulus = var1.getModulus();
      this.publicExponent = var1.getPublicExponent();
   }

   BCRSAPublicKey(SubjectPublicKeyInfo var1) {
      try {
         org.bc.asn1.pkcs.RSAPublicKey var2 = org.bc.asn1.pkcs.RSAPublicKey.getInstance(var1.parsePublicKey());
         this.modulus = var2.getModulus();
         this.publicExponent = var2.getPublicExponent();
      } catch (IOException var3) {
         throw new IllegalArgumentException("invalid info structure in RSA public key");
      }
   }

   public BigInteger getModulus() {
      return this.modulus;
   }

   public BigInteger getPublicExponent() {
      return this.publicExponent;
   }

   public String getAlgorithm() {
      return "RSA";
   }

   public String getFormat() {
      return "X.509";
   }

   public byte[] getEncoded() {
      return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), (ASN1Encodable)(new org.bc.asn1.pkcs.RSAPublicKey(this.getModulus(), this.getPublicExponent())));
   }

   public int hashCode() {
      return this.getModulus().hashCode() ^ this.getPublicExponent().hashCode();
   }

   public boolean equals(Object var1) {
      if (var1 == this) {
         return true;
      } else if (!(var1 instanceof RSAPublicKey)) {
         return false;
      } else {
         RSAPublicKey var2 = (RSAPublicKey)var1;
         return this.getModulus().equals(var2.getModulus()) && this.getPublicExponent().equals(var2.getPublicExponent());
      }
   }

   public String toString() {
      StringBuffer var1 = new StringBuffer();
      String var2 = System.getProperty("line.separator");
      var1.append("RSA Public Key").append(var2);
      var1.append("            modulus: ").append(this.getModulus().toString(16)).append(var2);
      var1.append("    public exponent: ").append(this.getPublicExponent().toString(16)).append(var2);
      return var1.toString();
   }
}
