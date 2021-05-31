package org.bc.crypto.modes.gcm;

public interface GCMExponentiator {
   void init(byte[] var1);

   void exponentiateX(long var1, byte[] var3);
}
