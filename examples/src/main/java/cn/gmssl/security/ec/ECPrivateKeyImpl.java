package cn.gmssl.security.ec;

import cn.gmssl.security.util.DerInputStream;
import cn.gmssl.security.util.DerOutputStream;
import cn.gmssl.security.util.DerValue;
import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import sun.security.pkcs.PKCS8Key;
import sun.security.x509.AlgorithmId;

public final class ECPrivateKeyImpl extends PKCS8Key implements ECPrivateKey {
   private static final long serialVersionUID = 88695385615075129L;
   private BigInteger s;
   private ECParameterSpec params;

   public ECPrivateKeyImpl(byte[] var1) throws InvalidKeyException {
      this.decode(var1);
   }

   public ECPrivateKeyImpl(BigInteger var1, ECParameterSpec var2) throws InvalidKeyException {
      this.s = var1;
      this.params = var2;
      this.algid = new AlgorithmId(AlgorithmId.EC_oid, ECParameters.getAlgorithmParameters(var2));

      try {
         DerOutputStream var3 = new DerOutputStream();
         var3.putInteger(1);
         byte[] var4 = ECParameters.trimZeroes(var1.toByteArray());
         var3.putOctetString(var4);
         DerValue var5 = new DerValue((byte)48, var3.toByteArray());
         var3.close();
         this.key = var5.toByteArray();
      } catch (IOException var6) {
         throw new InvalidKeyException(var6);
      }
   }

   public String getAlgorithm() {
      return "EC";
   }

   public BigInteger getS() {
      return this.s;
   }

   public ECParameterSpec getParams() {
      return this.params;
   }

   protected void parseKeyBits() throws InvalidKeyException {
      try {
         DerInputStream var1 = new DerInputStream(this.key);
         DerValue var2 = var1.getDerValue();
         if (var2.tag != 48) {
            throw new IOException("Not a SEQUENCE");
         } else {
            DerInputStream var3 = var2.data;
            int var4 = var3.getInteger();
            if (var4 != 1) {
               throw new IOException("Version must be 1");
            } else {
               byte[] var5 = var3.getOctetString();
               this.s = new BigInteger(1, var5);

               DerValue var6;
               do {
                  if (var3.available() == 0) {
                     AlgorithmParameters var9 = this.algid.getParameters();
                     if (var9 == null) {
                        throw new InvalidKeyException("EC domain parameters must be encoded in the algorithm identifier");
                     }

                     this.params = (ECParameterSpec)var9.getParameterSpec(ECParameterSpec.class);
                     return;
                  }

                  var6 = var3.getDerValue();
               } while(var6.isContextSpecific((byte)0) || var6.isContextSpecific((byte)1));

               throw new InvalidKeyException("Unexpected value: " + var6);
            }
         }
      } catch (IOException var7) {
         throw new InvalidKeyException("Invalid EC private key", var7);
      } catch (InvalidParameterSpecException var8) {
         throw new InvalidKeyException("Invalid EC private key", var8);
      }
   }

   public String toString() {
      return "Sun EC private key, " + this.params.getCurve().getField().getFieldSize() + " bits\n  private value:  " + this.s + "\n  parameters: " + this.params;
   }
}
