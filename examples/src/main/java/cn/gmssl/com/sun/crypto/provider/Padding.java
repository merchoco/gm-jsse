package cn.gmssl.com.sun.crypto.provider;

import javax.crypto.ShortBufferException;

interface Padding {
   void padWithLen(byte[] var1, int var2, int var3) throws ShortBufferException;

   int unpad(byte[] var1, int var2, int var3);

   int padLength(int var1);
}
