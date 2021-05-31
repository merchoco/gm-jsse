package org.bc.crypto.agreement.kdf;

import java.io.IOException;
import org.bc.asn1.ASN1EncodableVector;
import org.bc.asn1.ASN1ObjectIdentifier;
import org.bc.asn1.DERNull;
import org.bc.asn1.DEROctetString;
import org.bc.asn1.DERSequence;
import org.bc.asn1.DERTaggedObject;
import org.bc.asn1.x509.AlgorithmIdentifier;
import org.bc.crypto.DataLengthException;
import org.bc.crypto.DerivationFunction;
import org.bc.crypto.DerivationParameters;
import org.bc.crypto.Digest;
import org.bc.crypto.generators.KDF2BytesGenerator;
import org.bc.crypto.params.KDFParameters;

public class ECDHKEKGenerator implements DerivationFunction {
   private DerivationFunction kdf;
   private ASN1ObjectIdentifier algorithm;
   private int keySize;
   private byte[] z;

   public ECDHKEKGenerator(Digest var1) {
      this.kdf = new KDF2BytesGenerator(var1);
   }

   public void init(DerivationParameters var1) {
      DHKDFParameters var2 = (DHKDFParameters)var1;
      this.algorithm = var2.getAlgorithm();
      this.keySize = var2.getKeySize();
      this.z = var2.getZ();
   }

   public Digest getDigest() {
      return this.kdf.getDigest();
   }

   public int generateBytes(byte[] var1, int var2, int var3) throws DataLengthException, IllegalArgumentException {
      ASN1EncodableVector var4 = new ASN1EncodableVector();
      var4.add(new AlgorithmIdentifier(this.algorithm, DERNull.INSTANCE));
      var4.add(new DERTaggedObject(true, 2, new DEROctetString(this.integerToBytes(this.keySize))));

      try {
         this.kdf.init(new KDFParameters(this.z, (new DERSequence(var4)).getEncoded("DER")));
      } catch (IOException var6) {
         throw new IllegalArgumentException("unable to initialise kdf: " + var6.getMessage());
      }

      return this.kdf.generateBytes(var1, var2, var3);
   }

   private byte[] integerToBytes(int var1) {
      byte[] var2 = new byte[]{(byte)(var1 >> 24), (byte)(var1 >> 16), (byte)(var1 >> 8), (byte)var1};
      return var2;
   }
}
