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
import org.bc.pqc.asn1.McEliecePrivateKey;
import org.bc.pqc.asn1.McEliecePublicKey;
import org.bc.pqc.jcajce.spec.McEliecePrivateKeySpec;
import org.bc.pqc.jcajce.spec.McEliecePublicKeySpec;

public class McElieceKeyFactorySpi extends KeyFactorySpi {
   public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

   public PublicKey generatePublic(KeySpec var1) throws InvalidKeySpecException {
      if (var1 instanceof McEliecePublicKeySpec) {
         return new BCMcEliecePublicKey((McEliecePublicKeySpec)var1);
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
            return new BCMcEliecePublicKey(new McEliecePublicKeySpec("1.3.6.1.4.1.8301.3.1.3.4.1", var10, var8, var11));
         } catch (IOException var12) {
            throw new InvalidKeySpecException("Unable to decode X509EncodedKeySpec: " + var12.getMessage());
         }
      } else {
         throw new InvalidKeySpecException("Unsupported key specification: " + var1.getClass() + ".");
      }
   }

   public PrivateKey generatePrivate(KeySpec var1) throws InvalidKeySpecException {
      if (var1 instanceof McEliecePrivateKeySpec) {
         return new BCMcEliecePrivateKey((McEliecePrivateKeySpec)var1);
      } else if (var1 instanceof PKCS8EncodedKeySpec) {
         byte[] var2 = ((PKCS8EncodedKeySpec)var1).getEncoded();

         PrivateKeyInfo var3;
         try {
            var3 = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(var2));
         } catch (IOException var20) {
            throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec: " + var20);
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
            byte[] var15 = ((ASN1OctetString)var5.getObjectAt(7)).getOctets();
            byte[] var16 = ((ASN1OctetString)var5.getObjectAt(8)).getOctets();
            ASN1Sequence var17 = (ASN1Sequence)var5.getObjectAt(9);
            byte[][] var18 = new byte[var17.size()][];

            for(int var19 = 0; var19 < var17.size(); ++var19) {
               var18[var19] = ((ASN1OctetString)var17.getObjectAt(var19)).getOctets();
            }

            return new BCMcEliecePrivateKey(new McEliecePrivateKeySpec("1.3.6.1.4.1.8301.3.1.3.4.1", var8, var10, var11, var12, var13, var14, var15, var16, var18));
         } catch (IOException var21) {
            throw new InvalidKeySpecException("Unable to decode PKCS8EncodedKeySpec.");
         }
      } else {
         throw new InvalidKeySpecException("Unsupported key specification: " + var1.getClass() + ".");
      }
   }

   public KeySpec getKeySpec(Key var1, Class var2) throws InvalidKeySpecException {
      if (var1 instanceof BCMcEliecePrivateKey) {
         if (PKCS8EncodedKeySpec.class.isAssignableFrom(var2)) {
            return new PKCS8EncodedKeySpec(var1.getEncoded());
         }

         if (McEliecePrivateKeySpec.class.isAssignableFrom(var2)) {
            BCMcEliecePrivateKey var3 = (BCMcEliecePrivateKey)var1;
            return new McEliecePrivateKeySpec("1.3.6.1.4.1.8301.3.1.3.4.1", var3.getN(), var3.getK(), var3.getField(), var3.getGoppaPoly(), var3.getSInv(), var3.getP1(), var3.getP2(), var3.getH(), var3.getQInv());
         }
      } else {
         if (!(var1 instanceof BCMcEliecePublicKey)) {
            throw new InvalidKeySpecException("Unsupported key type: " + var1.getClass() + ".");
         }

         if (X509EncodedKeySpec.class.isAssignableFrom(var2)) {
            return new X509EncodedKeySpec(var1.getEncoded());
         }

         if (McEliecePublicKeySpec.class.isAssignableFrom(var2)) {
            BCMcEliecePublicKey var4 = (BCMcEliecePublicKey)var1;
            return new McEliecePublicKeySpec("1.3.6.1.4.1.8301.3.1.3.4.1", var4.getN(), var4.getT(), var4.getG());
         }
      }

      throw new InvalidKeySpecException("Unknown key specification: " + var2 + ".");
   }

   public Key translateKey(Key var1) throws InvalidKeyException {
      if (!(var1 instanceof BCMcEliecePrivateKey) && !(var1 instanceof BCMcEliecePublicKey)) {
         throw new InvalidKeyException("Unsupported key type.");
      } else {
         return var1;
      }
   }

   public PublicKey generatePublic(SubjectPublicKeyInfo var1) throws InvalidKeySpecException {
      try {
         ASN1Primitive var2 = var1.parsePublicKey();
         McEliecePublicKey var3 = McEliecePublicKey.getInstance(var2);
         return new BCMcEliecePublicKey(var3.getOID().getId(), var3.getN(), var3.getT(), var3.getG());
      } catch (IOException var4) {
         throw new InvalidKeySpecException("Unable to decode X509EncodedKeySpec");
      }
   }

   public PrivateKey generatePrivate(PrivateKeyInfo var1) throws InvalidKeySpecException {
      try {
         ASN1Primitive var2 = var1.parsePrivateKey().toASN1Primitive();
         McEliecePrivateKey var3 = McEliecePrivateKey.getInstance(var2);
         return new BCMcEliecePrivateKey(var3.getOID().getId(), var3.getN(), var3.getK(), var3.getField(), var3.getGoppaPoly(), var3.getSInv(), var3.getP1(), var3.getP2(), var3.getH(), var3.getQInv());
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
