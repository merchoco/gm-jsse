package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.io.Serializable;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SealedObject;

final class SealedObjectForKeyProtector extends SealedObject {
   static final long serialVersionUID = -3650226485480866989L;

   SealedObjectForKeyProtector(Serializable var1, Cipher var2) throws IOException, IllegalBlockSizeException {
      super(var1, var2);
   }

   SealedObjectForKeyProtector(SealedObject var1) {
      super(var1);
   }

   AlgorithmParameters getParameters() {
      AlgorithmParameters var1 = null;
      if (super.encodedParams != null) {
         try {
            var1 = AlgorithmParameters.getInstance("PBE", "SunJCE");
            var1.init(super.encodedParams);
         } catch (NoSuchProviderException var3) {
            ;
         } catch (NoSuchAlgorithmException var4) {
            ;
         } catch (IOException var5) {
            ;
         }
      }

      return var1;
   }
}
