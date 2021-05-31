package org.bc.crypto.agreement.kdf;

import java.io.IOException;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.DERObjectIdentifier;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.DerivationFunction;
import org.bc.crypto.DerivationParameters;
import org.bc.crypto.Digest;

public class DHKEKGenerator implements DerivationFunction {
   private final Digest digest;
   private DERObjectIdentifier algorithm;
   private int keySize;
   private byte[] z;
   private byte[] partyAInfo;

   public DHKEKGenerator(Digest var1) {
      this.digest = var1;
   }

   public void init(DerivationParameters var1) {
      DHKDFParameters var2 = (DHKDFParameters)var1;
      this.algorithm = var2.getAlgorithm();
      this.keySize = var2.getKeySize();
      this.z = var2.getZ();
      this.partyAInfo = var2.getExtraInfo();
   }

   public Digest getDigest() {
      return this.digest;
   }

   public int generateBytes(byte[] var1, int var2, int var3) throws DataLengthException, IllegalArgumentException {
      if (var1.length - var3 < var2) {
         throw new DataLengthException("output buffer too small");
      } else {
         long var4 = (long)var3;
         int var6 = this.digest.getDigestSize();
         if (var4 > 8589934591L) {
            throw new IllegalArgumentException("Output length too large");
         } else {
            int var7 = (int)((var4 + (long)var6 - 1L) / (long)var6);
            byte[] var8 = new byte[this.digest.getDigestSize()];
            int var9 = 1;

            for(int var10 = 0; var10 < var7; ++var10) {
               this.digest.update(this.z, 0, this.z.length);
               ASN1EncodableVector var11 = new ASN1EncodableVector();
               ASN1EncodableVector var12 = new ASN1EncodableVector();
               var12.add(this.algorithm);
               var12.add(new DEROctetString(this.integerToBytes(var9)));
               var11.add(new DERSequence(var12));
               if (this.partyAInfo != null) {
                  var11.add(new DERTaggedObject(true, 0, new DEROctetString(this.partyAInfo)));
               }

               var11.add(new DERTaggedObject(true, 2, new DEROctetString(this.integerToBytes(this.keySize))));

               try {
                  byte[] var13 = (new DERSequence(var11)).getEncoded("DER");
                  this.digest.update(var13, 0, var13.length);
               } catch (IOException var14) {
                  throw new IllegalArgumentException("unable to encode parameter info: " + var14.getMessage());
               }

               this.digest.doFinal(var8, 0);
               if (var3 > var6) {
                  System.arraycopy(var8, 0, var1, var2, var6);
                  var2 += var6;
                  var3 -= var6;
               } else {
                  System.arraycopy(var8, 0, var1, var2, var3);
               }

               ++var9;
            }

            this.digest.reset();
            return var3;
         }
      }
   }

   private byte[] integerToBytes(int var1) {
      byte[] var2 = new byte[]{(byte)(var1 >> 24), (byte)(var1 >> 16), (byte)(var1 >> 8), (byte)var1};
      return var2;
   }
}
