package org.bc.crypto;

public interface SignerWithRecovery extends Signer {
   boolean hasFullMessage();

   byte[] getRecoveredMessage();

   void updateWithRecoveredMessage(byte[] var1) throws InvalidCipherTextException;
}
