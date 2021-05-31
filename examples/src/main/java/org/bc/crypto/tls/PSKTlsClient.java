package org.bc.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public abstract class PSKTlsClient implements TlsClient {
   protected TlsCipherFactory cipherFactory;
   protected TlsPSKIdentity pskIdentity;
   protected TlsClientContext context;
   protected int selectedCompressionMethod;
   protected int selectedCipherSuite;

   public PSKTlsClient(TlsPSKIdentity var1) {
      this(new DefaultTlsCipherFactory(), var1);
   }

   public PSKTlsClient(TlsCipherFactory var1, TlsPSKIdentity var2) {
      this.cipherFactory = var1;
      this.pskIdentity = var2;
   }

   public ProtocolVersion getClientVersion() {
      return ProtocolVersion.TLSv10;
   }

   public void init(TlsClientContext var1) {
      this.context = var1;
   }

   public int[] getCipherSuites() {
      return new int[]{145, 144, 143, 142, 149, 148, 147, 146, 141, 140, 139, 138};
   }

   public Hashtable getClientExtensions() throws IOException {
      return null;
   }

   public short[] getCompressionMethods() {
      return new short[1];
   }

   public void notifyServerVersion(ProtocolVersion var1) throws IOException {
      if (!ProtocolVersion.TLSv10.equals(var1)) {
         throw new TlsFatalAlert((short)47);
      }
   }

   public void notifySessionID(byte[] var1) {
   }

   public void notifySelectedCipherSuite(int var1) {
      this.selectedCipherSuite = var1;
   }

   public void notifySelectedCompressionMethod(short var1) {
      this.selectedCompressionMethod = var1;
   }

   public void notifySecureRenegotiation(boolean var1) throws IOException {
   }

   public void processServerExtensions(Hashtable var1) {
   }

   public TlsKeyExchange getKeyExchange() throws IOException {
      switch(this.selectedCipherSuite) {
      case 138:
      case 139:
      case 140:
      case 141:
         return this.createPSKKeyExchange(13);
      case 142:
      case 143:
      case 144:
      case 145:
         return this.createPSKKeyExchange(14);
      case 146:
      case 147:
      case 148:
      case 149:
         return this.createPSKKeyExchange(15);
      default:
         throw new TlsFatalAlert((short)80);
      }
   }

   public TlsCompression getCompression() throws IOException {
      switch(this.selectedCompressionMethod) {
      case 0:
         return new TlsNullCompression();
      default:
         throw new TlsFatalAlert((short)80);
      }
   }

   public TlsCipher getCipher() throws IOException {
      switch(this.selectedCipherSuite) {
      case 138:
      case 142:
      case 146:
         return this.cipherFactory.createCipher(this.context, 2, 2);
      case 139:
      case 143:
      case 147:
         return this.cipherFactory.createCipher(this.context, 7, 2);
      case 140:
      case 144:
      case 148:
         return this.cipherFactory.createCipher(this.context, 8, 2);
      case 141:
      case 145:
      case 149:
         return this.cipherFactory.createCipher(this.context, 9, 2);
      default:
         throw new TlsFatalAlert((short)80);
      }
   }

   protected TlsKeyExchange createPSKKeyExchange(int var1) {
      return new TlsPSKKeyExchange(this.context, var1, this.pskIdentity);
   }
}
