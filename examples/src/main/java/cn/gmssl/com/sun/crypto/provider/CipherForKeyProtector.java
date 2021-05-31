package cn.gmssl.com.sun.crypto.provider;

import java.security.Provider;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;

final class CipherForKeyProtector extends Cipher {
   protected CipherForKeyProtector(CipherSpi var1, Provider var2, String var3) {
      super(var1, var2, var3);
   }
}
