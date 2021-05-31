package cn.gmssl.jce.skf;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface ICryptoProvider {
   X509Certificate getCert(int var1) throws Exception;

   PrivateKey getPrivateKey(int var1) throws Exception;

   byte[] doSign(byte[] var1, int var2, int var3) throws Exception;
}
