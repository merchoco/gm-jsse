package cn.gmssl.sun.security.internal.spec;

import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/** @deprecated */
@Deprecated
public class TlsKeyMaterialSpec implements KeySpec, SecretKey {
   static final long serialVersionUID = 812912859129525028L;
   private final SecretKey clientMacKey;
   private final SecretKey serverMacKey;
   private final SecretKey clientCipherKey;
   private final SecretKey serverCipherKey;
   private final IvParameterSpec clientIv;
   private final IvParameterSpec serverIv;

   public TlsKeyMaterialSpec(SecretKey var1, SecretKey var2) {
      this(var1, var2, (SecretKey)null, (IvParameterSpec)null, (SecretKey)null, (IvParameterSpec)null);
   }

   public TlsKeyMaterialSpec(SecretKey var1, SecretKey var2, SecretKey var3, SecretKey var4) {
      this(var1, var2, var3, (IvParameterSpec)null, var4, (IvParameterSpec)null);
   }

   public TlsKeyMaterialSpec(SecretKey var1, SecretKey var2, SecretKey var3, IvParameterSpec var4, SecretKey var5, IvParameterSpec var6) {
      if (var1 != null && var2 != null) {
         this.clientMacKey = var1;
         this.serverMacKey = var2;
         this.clientCipherKey = var3;
         this.serverCipherKey = var5;
         this.clientIv = var4;
         this.serverIv = var6;
      } else {
         throw new NullPointerException("MAC keys must not be null");
      }
   }

   public String getAlgorithm() {
      return "TlsKeyMaterial";
   }

   public String getFormat() {
      return null;
   }

   public byte[] getEncoded() {
      return null;
   }

   public SecretKey getClientMacKey() {
      return this.clientMacKey;
   }

   public SecretKey getServerMacKey() {
      return this.serverMacKey;
   }

   public SecretKey getClientCipherKey() {
      return this.clientCipherKey;
   }

   public IvParameterSpec getClientIv() {
      return this.clientIv;
   }

   public SecretKey getServerCipherKey() {
      return this.serverCipherKey;
   }

   public IvParameterSpec getServerIv() {
      return this.serverIv;
   }
}
