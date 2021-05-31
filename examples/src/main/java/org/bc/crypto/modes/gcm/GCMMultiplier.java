package org.bc.crypto.modes.gcm;

public interface GCMMultiplier {
   void init(byte[] var1);

   void multiplyH(byte[] var1);
}
