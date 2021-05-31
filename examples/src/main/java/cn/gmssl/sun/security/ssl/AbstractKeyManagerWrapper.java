package cn.gmssl.sun.security.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

final class AbstractKeyManagerWrapper extends X509ExtendedKeyManager {
   private final X509KeyManager km;

   AbstractKeyManagerWrapper(X509KeyManager var1) {
      this.km = var1;
   }

   public String[] getClientAliases(String var1, Principal[] var2) {
      return this.km.getClientAliases(var1, var2);
   }

   public String chooseClientAlias(String[] var1, Principal[] var2, Socket var3) {
      return this.km.chooseClientAlias(var1, var2, var3);
   }

   public String[] getServerAliases(String var1, Principal[] var2) {
      return this.km.getServerAliases(var1, var2);
   }

   public String chooseServerAlias(String var1, Principal[] var2, Socket var3) {
      return this.km.chooseServerAlias(var1, var2, var3);
   }

   public X509Certificate[] getCertificateChain(String var1) {
      return this.km.getCertificateChain(var1);
   }

   public PrivateKey getPrivateKey(String var1) {
      return this.km.getPrivateKey(var1);
   }
}
