package cn.gmssl.security.util;

import java.io.IOException;
import java.io.OutputStream;

public interface DerEncoder {
   void derEncode(OutputStream var1) throws IOException;
}
