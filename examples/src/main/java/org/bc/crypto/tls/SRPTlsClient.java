package org.bc.crypto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import org.bc.util.Arrays;
import org.bc.util.Integers;

public abstract class SRPTlsClient implements TlsClient {
   public static final Integer EXT_SRP = Integers.valueOf(12);
   protected TlsCipherFactory cipherFactory;
   protected byte[] identity;
   protected byte[] password;
   protected TlsClientContext context;
   protected int selectedCompressionMethod;
   protected int selectedCipherSuite;

   public SRPTlsClient(byte[] var1, byte[] var2) {
      this(new DefaultTlsCipherFactory(), var1, var2);
   }

   public SRPTlsClient(TlsCipherFactory var1, byte[] var2, byte[] var3) {
      this.cipherFactory = var1;
      this.identity = Arrays.clone(var2);
      this.password = Arrays.clone(var3);
   }

   public void init(TlsClientContext var1) {
      this.context = var1;
   }

   public ProtocolVersion getClientVersion() {
      return ProtocolVersion.TLSv10;
   }

   public int[] getCipherSuites() {
      return new int[]{49186, 49183, 49180, 49185, 49182, 49179, 49184, 49181, 49178};
   }

   public Hashtable getClientExtensions() throws IOException {
      Hashtable var1 = new Hashtable();
      ByteArrayOutputStream var2 = new ByteArrayOutputStream();
      TlsUtils.writeOpaque8(this.identity, var2);
      var1.put(EXT_SRP, var2.toByteArray());
      return var1;
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
      case 49178:
      case 49181:
      case 49184:
         return this.createSRPKeyExchange(21);
      case 49179:
      case 49182:
      case 49185:
         return this.createSRPKeyExchange(23);
      case 49180:
      case 49183:
      case 49186:
         return this.createSRPKeyExchange(22);
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
      case 49178:
      case 49179:
      case 49180:
         return this.cipherFactory.createCipher(this.context, 7, 2);
      case 49181:
      case 49182:
      case 49183:
         return this.cipherFactory.createCipher(this.context, 8, 2);
      case 49184:
      case 49185:
      case 49186:
         return this.cipherFactory.createCipher(this.context, 9, 2);
      default:
         throw new TlsFatalAlert((short)80);
      }
   }

   protected TlsKeyExchange createSRPKeyExchange(int var1) {
      return new TlsSRPKeyExchange(this.context, var1, this.identity, this.password);
   }
}
