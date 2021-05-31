package org.bc.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public interface TlsClient {
   void init(TlsClientContext var1);

   ProtocolVersion getClientVersion();

   int[] getCipherSuites();

   short[] getCompressionMethods();

   Hashtable getClientExtensions() throws IOException;

   void notifyServerVersion(ProtocolVersion var1) throws IOException;

   void notifySessionID(byte[] var1);

   void notifySelectedCipherSuite(int var1);

   void notifySelectedCompressionMethod(short var1);

   void notifySecureRenegotiation(boolean var1) throws IOException;

   void processServerExtensions(Hashtable var1);

   TlsKeyExchange getKeyExchange() throws IOException;

   TlsAuthentication getAuthentication() throws IOException;

   TlsCompression getCompression() throws IOException;

   TlsCipher getCipher() throws IOException;
}
