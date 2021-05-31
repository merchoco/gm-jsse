package cn.gmssl.com.sun.crypto.provider;

import java.security.InvalidKeyException;

abstract class SymmetricCipher {
   abstract int getBlockSize();

   abstract void init(boolean var1, String var2, byte[] var3) throws InvalidKeyException;

   abstract void encryptBlock(byte[] var1, int var2, byte[] var3, int var4);

   abstract void decryptBlock(byte[] var1, int var2, byte[] var3, int var4);
}
