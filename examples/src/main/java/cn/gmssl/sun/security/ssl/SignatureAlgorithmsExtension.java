package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import javax.net.ssl.SSLProtocolException;

final class SignatureAlgorithmsExtension extends HelloExtension {
   private Collection<SignatureAndHashAlgorithm> algorithms;
   private int algorithmsLen;

   SignatureAlgorithmsExtension(Collection<SignatureAndHashAlgorithm> var1) {
      super(ExtensionType.EXT_SIGNATURE_ALGORITHMS);
      this.algorithms = new ArrayList(var1);
      this.algorithmsLen = SignatureAndHashAlgorithm.sizeInRecord() * this.algorithms.size();
   }

   SignatureAlgorithmsExtension(HandshakeInStream var1, int var2) throws IOException {
      super(ExtensionType.EXT_SIGNATURE_ALGORITHMS);
      this.algorithmsLen = var1.getInt16();
      if (this.algorithmsLen != 0 && this.algorithmsLen + 2 == var2) {
         this.algorithms = new ArrayList();
         int var3 = this.algorithmsLen;

         for(int var4 = 0; var3 > 1; var3 -= 2) {
            int var5 = var1.getInt8();
            int var6 = var1.getInt8();
            ++var4;
            SignatureAndHashAlgorithm var7 = SignatureAndHashAlgorithm.valueOf(var5, var6, var4);
            this.algorithms.add(var7);
         }

         if (var3 != 0) {
            throw new SSLProtocolException("Invalid server_name extension");
         }
      } else {
         throw new SSLProtocolException("Invalid " + this.type + " extension");
      }
   }

   Collection<SignatureAndHashAlgorithm> getSignAlgorithms() {
      return this.algorithms;
   }

   int length() {
      return 6 + this.algorithmsLen;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putInt16(this.type.id);
      var1.putInt16(this.algorithmsLen + 2);
      var1.putInt16(this.algorithmsLen);
      Iterator var3 = this.algorithms.iterator();

      while(var3.hasNext()) {
         SignatureAndHashAlgorithm var2 = (SignatureAndHashAlgorithm)var3.next();
         var1.putInt8(var2.getHashValue());
         var1.putInt8(var2.getSignatureValue());
      }

   }

   public String toString() {
      StringBuffer var1 = new StringBuffer();
      boolean var2 = false;
      Iterator var4 = this.algorithms.iterator();

      while(var4.hasNext()) {
         SignatureAndHashAlgorithm var3 = (SignatureAndHashAlgorithm)var4.next();
         if (var2) {
            var1.append(", " + var3.getAlgorithmName());
         } else {
            var1.append(var3.getAlgorithmName());
            var2 = true;
         }
      }

      return "Extension " + this.type + ", signature_algorithms: " + var1;
   }
}
