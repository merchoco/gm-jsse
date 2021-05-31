package org.bc.crypto.tls;

import java.io.IOException;
import java.util.Hashtable;

public abstract class DefaultTlsClient implements TlsClient {
   protected TlsCipherFactory cipherFactory;
   protected TlsClientContext context;
   protected int selectedCipherSuite;
   protected int selectedCompressionMethod;

   public DefaultTlsClient() {
      this(new DefaultTlsCipherFactory());
   }

   public DefaultTlsClient(TlsCipherFactory var1) {
      this.cipherFactory = var1;
   }

   public void init(TlsClientContext var1) {
      this.context = var1;
   }

   public ProtocolVersion getClientVersion() {
      return ProtocolVersion.TLSv10;
   }

   public int[] getCipherSuites() {
      return new int[]{57, 56, 51, 50, 22, 19, 53, 47, 10, 5};
   }

   public Hashtable getClientExtensions() {
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
      case 5:
      case 10:
      case 47:
      case 53:
         return this.createRSAKeyExchange();
      case 13:
      case 48:
      case 54:
         return this.createDHKeyExchange(7);
      case 16:
      case 49:
      case 55:
         return this.createDHKeyExchange(9);
      case 19:
      case 50:
      case 56:
         return this.createDHEKeyExchange(3);
      case 22:
      case 51:
      case 57:
         return this.createDHEKeyExchange(5);
      case 49154:
      case 49155:
      case 49156:
      case 49157:
         return this.createECDHKeyExchange(16);
      case 49159:
      case 49160:
      case 49161:
      case 49162:
         return this.createECDHEKeyExchange(17);
      case 49164:
      case 49165:
      case 49166:
      case 49167:
         return this.createECDHKeyExchange(18);
      case 49169:
      case 49170:
      case 49171:
      case 49172:
         return this.createECDHEKeyExchange(19);
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
      case 5:
      case 49154:
      case 49159:
      case 49164:
      case 49169:
         return this.cipherFactory.createCipher(this.context, 2, 2);
      case 10:
      case 13:
      case 16:
      case 19:
      case 22:
      case 49155:
      case 49160:
      case 49165:
      case 49170:
         return this.cipherFactory.createCipher(this.context, 7, 2);
      case 47:
      case 48:
      case 49:
      case 50:
      case 51:
      case 49156:
      case 49161:
      case 49166:
      case 49171:
         return this.cipherFactory.createCipher(this.context, 8, 2);
      case 53:
      case 54:
      case 55:
      case 56:
      case 57:
      case 49157:
      case 49162:
      case 49167:
      case 49172:
         return this.cipherFactory.createCipher(this.context, 9, 2);
      default:
         throw new TlsFatalAlert((short)80);
      }
   }

   protected TlsKeyExchange createDHKeyExchange(int var1) {
      return new TlsDHKeyExchange(this.context, var1);
   }

   protected TlsKeyExchange createDHEKeyExchange(int var1) {
      return new TlsDHEKeyExchange(this.context, var1);
   }

   protected TlsKeyExchange createECDHKeyExchange(int var1) {
      return new TlsECDHKeyExchange(this.context, var1);
   }

   protected TlsKeyExchange createECDHEKeyExchange(int var1) {
      return new TlsECDHEKeyExchange(this.context, var1);
   }

   protected TlsKeyExchange createRSAKeyExchange() {
      return new TlsRSAKeyExchange(this.context);
   }
}
