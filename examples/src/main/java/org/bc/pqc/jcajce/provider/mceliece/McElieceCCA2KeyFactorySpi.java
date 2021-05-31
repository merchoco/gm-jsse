package org.bc.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bc.asn1.ASN1Integer;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.ASN1OctetString;
import org.bc.asn1.ASN1Primitive;
import org.bc.asn1.ASN1Sequence;
import org.bc.asn1.pkcs.PrivateKeyInfo;
import org.bc.asn1.x509.SubjectPublicKeyInfo;
import org.bc.pqc.asn1.McElieceCCA2PrivateKey;
import org.bc.pqc.asn1.McElieceCCA2PublicKey;
import org.bc.pqc.jcajce.spec.McElieceCCA2PrivateKeySpec;
import org.bc.pqc.jcajce.spec.McElieceCCA2PublicKeySpec;

public class McElieceCCA2KeyFactorySpi extends KeyFactorySpi {
   public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2";

   public PublicKey generatePublic(KeySpec var1) throws InvalidKeySpecException {
      if (var1 instanceof McElieceCCA2PublicKeySpec) {
         return new BCMcElieceCCA2PublicKey((McElieceCCA2PublicKeySpec)var1);
      } else if (var1 instanceof X509EncodedKeySpec) {
         byte[] var2 = ((X509EncodedKeySpec)var1).getEncoded();

         SubjectPublicKeyInfo var3;
         try {
            var3 = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(var2));
         } catch (IOException var13) {
            throw new InvalidKeySpecException(var13.toString());
         }

         try {
            ASN1Primitive var4 = var3.parsePublicKey();
            ASN1Sequence var5 = (ASN1Sequence)var4;
            String var6 = ((ASN1ObjectIdentifier)var5.getObjectAt(0)).toString();
            BigInteger var7 = ((ASN1Integer)var5.getObjectAt(1)).getValue();
            int var8 = var7.intValue();
            BigInteger var9 = ((ASN1Integer)var5.getObjectAt(2)).getValue();
            int var10 = var9.intValue();
            byte[] var11 = ((ASN1OctetString)var5.getObjectAt(3)).getOctets();
            return new BCMcElieceCCA2PublicKey(new McElieceCCA2PublicKeySpec("1.3.6.1.4.1.8301.3.1.3.4.2", var8, var10, var11));
         } catch (IOException var12) {
            throw new InvalidKeySpecException("Unable to decode X509EncodedKeySpec: " + var12.getMessage());
         }
      } else {
         throw new InvalidKeySpecException("Unsupported key specification: " + var1.getClass() + ".");
      }
   }

   public PrivateKey generatePrivate(KeySpec var1) throws InvalidKeySpecException {
      if (var1 instanceof McElieceCCA2PrivateKeySpec) {
         return new BCMcElieceCCA2PrivateKey((McElieceCCA2PrivateKeySpec)var1);
      } else if (var1 instanceof PKCS8EncodedKeySpec) {
         byte[] var2 = ((PKCS8EncodedKeySpec)var1).getEncoded();

         PrivateKeyInfo var3;
         try {
            var3 = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(var2));
         } catch (IOException var18) {
            throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec: " + var18);
         }

         try {
            ASN1Primitive var4 = var3.parsePrivateKey().toASN1Primitive();
            ASN1Sequence var5 = (ASN1Sequence)var4;
            String var6 = ((ASN1ObjectIdentifier)var5.getObjectAt(0)).toString();
            BigInteger var7 = ((ASN1Integer)var5.getObjectAt(1)).getValue();
            int var8 = var7.intValue();
            BigInteger var9 = ((ASN1Integer)var5.getObjectAt(2)).getValue();
            int var10 = var9.intValue();
            byte[] var11 = ((ASN1OctetString)var5.getObjectAt(3)).getOctets();
            byte[] var12 = ((ASN1OctetString)var5.getObjectAt(4)).getOctets();
            byte[] var13 = ((ASN1OctetString)var5.getObjectAt(5)).getOctets();
            byte[] var14 = ((ASN1OctetString)var5.getObjectAt(6)).getOctets();
            ASN1Sequence var15 = (ASN1Sequence)var5.getObjectAt(7);
            byte[][] var16 = new byte[var15.size()][];

            for(int var17 = 0; var17 < var15.size(); ++var17) {
               var16[var17] = ((ASN1OctetString)var15.getObjectAt(var17)).getOctets();
            }

            return new BCMcElieceCCA2PrivateKey(new McElieceCCA2PrivateKeySpec("1.3.6.1.4.1.8301.3.1.3.4.2", var8, var10, var11, var12, var13, var14, var16));
         } catch (IOException var19) {
            throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec.");
         }
      } else {
         throw new InvalidKeySpecException("Unsupported key specification: " + var1.getClass() + ".");
      }
   }

   public KeySpec getKeySpec(Key var1, Class var2) throws InvalidKeySpecException {
      if (var1 instanceof BCMcElieceCCA2PrivateKey) {
         if (PKCS8EncodedKeySpec.class.isAssignableFrom(var2)) {
            return new PKCS8EncodedKeySpec(var1.getEncoded());
         }

         if (McElieceCCA2PrivateKeySpec.class.isAssignableFrom(var2)) {
            BCMcElieceCCA2PrivateKey var3 = (BCMcElieceCCA2PrivateKey)var1;
            return new McElieceCCA2PrivateKeySpec("1.3.6.1.4.1.8301.3.1.3.4.2", var3.getN(), var3.getK(), var3.getField(), var3.getGoppaPoly(), var3.getP(), var3.getH(), var3.getQInv());
         }
      } else {
         if (!(var1 instanceof BCMcElieceCCA2PublicKey)) {
            throw new InvalidKeySpecException("Unsupported key type: " + var1.getClass() + ".");
         }

         if (X509EncodedKeySpec.class.isAssignableFrom(var2)) {
            return new X509EncodedKeySpec(var1.getEncoded());
         }

         if (McElieceCCA2PublicKeySpec.class.isAssignableFrom(var2)) {
            BCMcElieceCCA2PublicKey var4 = (BCMcElieceCCA2PublicKey)var1;
            return new McElieceCCA2PublicKeySpec("1.3.6.1.4.1.8301.3.1.3.4.2", var4.getN(), var4.getT(), var4.getG());
         }
      }

      throw new InvalidKeySpecException("Unknown key specification: " + var2 + ".");
   }

   public Key translateKey(Key var1) throws InvalidKeyException {
      if (!(var1 instanceof BCMcElieceCCA2PrivateKey) && !(var1 instanceof BCMcElieceCCA2PublicKey)) {
         throw new InvalidKeyException("Unsupported key type.");
      } else {
         return var1;
      }
   }

   public PublicKey generatePublic(SubjectPublicKeyInfo var1) throws InvalidKeySpecException {
      try {
         ASN1Primitive var2 = var1.parsePublicKey();
         McElieceCCA2PublicKey var3 = McElieceCCA2PublicKey.getInstance((ASN1Sequence)var2);
         return new BCMcElieceCCA2PublicKey(var3.getOID().getId(), var3.getN(), var3.getT(), var3.getG());
      } catch (IOException var4) {
         throw new InvalidKeySpecException("Unable to decode X509EncodedKeySpec");
      }
   }

   public PrivateKey generatePrivate(PrivateKeyInfo var1) throws InvalidKeySpecException {
      try {
         ASN1Primitive var2 = var1.parsePrivateKey().toASN1Primitive();
         McElieceCCA2PrivateKey var3 = McElieceCCA2PrivateKey.getInstance(var2);
         return new BCMcElieceCCA2PrivateKey(var3.getOID().getId(), var3.getN(), var3.getK(), var3.getField(), var3.getGoppaPoly(), var3.getP(), var3.getH(), var3.getQInv());
      } catch (IOException var4) {
         throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec");
      }
   }

   protected PublicKey engineGeneratePublic(KeySpec var1) throws InvalidKeySpecException {
      return null;
   }

   protected PrivateKey engineGeneratePrivate(KeySpec var1) throws InvalidKeySpecException {
      return null;
   }

   protected KeySpec engineGetKeySpec(Key var1, Class var2) throws InvalidKeySpecException {
      return null;
   }

   protected Key engineTranslateKey(Key var1) throws InvalidKeyException {
      return null;
   }
}
