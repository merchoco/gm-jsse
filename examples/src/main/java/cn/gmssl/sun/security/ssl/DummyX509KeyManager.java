package cn.gmssl.sun.security.ssl;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

final class DummyX509KeyManager extends X509ExtendedKeyManager {
   static final X509ExtendedKeyManager INSTANCE = new DummyX509KeyManager();

   public String[] getClientAliases(String var1, Principal[] var2) {
      return null;
   }

   public String chooseClientAlias(String[] var1, Principal[] var2, Socket var3) {
      return null;
   }

   public String chooseEngineClientAlias(String[] var1, Principal[] var2, SSLEngine var3) {
      return null;
   }

   public String[] getServerAliases(String var1, Principal[] var2) {
      return null;
   }

   public String chooseServerAlias(String var1, Principal[] var2, Socket var3) {
      return null;
   }

   public String chooseEngineServerAlias(String var1, Principal[] var2, SSLEngine var3) {
      return null;
   }

   public X509Certificate[] getCertificateChain(String var1) {
      return null;
   }

   public PrivateKey getPrivateKey(String var1) {
      return null;
   }
}
