package org.bc.crypto.tls;

import java.security.SecureRandom;

public interface TlsClientContext {
   SecureRandom getSecureRandom();

   SecurityParameters getSecurityParameters();

   ProtocolVersion getClientVersion();

   ProtocolVersion getServerVersion();

   Object getUserObject();

   void setUserObject(Object var1);
}
