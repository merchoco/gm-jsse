package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgorithmId;

final class EncryptedPrivateKeyInfo {
   private AlgorithmId algid;
   private byte[] encryptedData;
   private byte[] encoded;

   EncryptedPrivateKeyInfo(byte[] var1) throws IOException {
      DerValue var2 = new DerValue(var1);
      DerValue[] var3 = new DerValue[]{var2.data.getDerValue(), var2.data.getDerValue()};
      if (var2.data.available() != 0) {
         throw new IOException("overrun, bytes = " + var2.data.available());
      } else {
         this.algid = AlgorithmId.parse(var3[0]);
         if (var3[0].data.available() != 0) {
            throw new IOException("encryptionAlgorithm field overrun");
         } else {
            this.encryptedData = var3[1].getOctetString();
            if (var3[1].data.available() != 0) {
               throw new IOException("encryptedData field overrun");
            } else {
               this.encoded = (byte[])var1.clone();
            }
         }
      }
   }

   EncryptedPrivateKeyInfo(AlgorithmId var1, byte[] var2) {
      this.algid = var1;
      this.encryptedData = (byte[])var2.clone();
      this.encoded = null;
   }

   AlgorithmId getAlgorithm() {
      return this.algid;
   }

   byte[] getEncryptedData() {
      return (byte[])this.encryptedData.clone();
   }

   byte[] getEncoded() throws IOException {
      if (this.encoded != null) {
         return (byte[])this.encoded.clone();
      } else {
         DerOutputStream var1 = new DerOutputStream();
         DerOutputStream var2 = new DerOutputStream();
         this.algid.encode(var2);
         var2.putOctetString(this.encryptedData);
         var1.write((byte)48, var2);
         this.encoded = var1.toByteArray();
         var1.close();
         return (byte[])this.encoded.clone();
      }
   }
}
