package cn.gmssl.sun.security.internal.interfaces;

import javax.crypto.SecretKey;

/** @deprecated */
@Deprecated
public interface TlsMasterSecret extends SecretKey {
   long serialVersionUID = -461748105810469773L;

   int getMajorVersion();

   int getMinorVersion();
}
