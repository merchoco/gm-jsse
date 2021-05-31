package cn.gmssl.sun.security.ssl;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SSLProtocolException;

final class ServerNameExtension extends HelloExtension {
   static final int NAME_HOST_NAME = 0;
   private List<ServerNameExtension.ServerName> names;
   private int listLength;

   ServerNameExtension(List<String> var1) throws IOException {
      super(ExtensionType.EXT_SERVER_NAME);
      this.listLength = 0;
      this.names = new ArrayList(var1.size());
      Iterator var3 = var1.iterator();

      while(var3.hasNext()) {
         String var2 = (String)var3.next();
         if (var2 != null && var2.length() != 0) {
            ServerNameExtension.ServerName var4 = new ServerNameExtension.ServerName(0, var2);
            this.names.add(var4);
            this.listLength += var4.length;
         }
      }

      if (this.names.size() > 1) {
         throw new SSLProtocolException("The ServerNameList MUST NOT contain more than one name of the same name_type");
      } else if (this.listLength == 0) {
         throw new SSLProtocolException("The ServerNameList cannot be empty");
      }
   }

   ServerNameExtension(HandshakeInStream var1, int var2) throws IOException {
      super(ExtensionType.EXT_SERVER_NAME);
      int var3 = var2;
      if (var2 >= 2) {
         this.listLength = var1.getInt16();
         if (this.listLength == 0 || this.listLength + 2 != var2) {
            throw new SSLProtocolException("Invalid " + this.type + " extension");
         }

         var3 = var2 - 2;

         ServerNameExtension.ServerName var4;
         for(this.names = new ArrayList(); var3 > 0; var3 -= var4.length) {
            var4 = new ServerNameExtension.ServerName(var1);
            this.names.add(var4);
         }
      } else if (var2 == 0) {
         this.listLength = 0;
         this.names = Collections.emptyList();
      }

      if (var3 != 0) {
         throw new SSLProtocolException("Invalid server_name extension");
      }
   }

   int length() {
      return this.listLength == 0 ? 4 : 6 + this.listLength;
   }

   void send(HandshakeOutStream var1) throws IOException {
      var1.putInt16(this.type.id);
      var1.putInt16(this.listLength + 2);
      if (this.listLength != 0) {
         var1.putInt16(this.listLength);
         Iterator var3 = this.names.iterator();

         while(var3.hasNext()) {
            ServerNameExtension.ServerName var2 = (ServerNameExtension.ServerName)var3.next();
            var1.putInt8(var2.type);
            var1.putBytes16(var2.data);
         }
      }

   }

   public String toString() {
      StringBuffer var1 = new StringBuffer();
      Iterator var3 = this.names.iterator();

      while(var3.hasNext()) {
         ServerNameExtension.ServerName var2 = (ServerNameExtension.ServerName)var3.next();
         var1.append("[" + var2 + "]");
      }

      return "Extension " + this.type + ", server_name: " + var1;
   }

   static class ServerName {
      final int length;
      final int type;
      final byte[] data;
      final String hostname;

      ServerName(int var1, String var2) throws IOException {
         this.type = var1;
         this.hostname = var2;
         this.data = var2.getBytes("UTF8");
         this.length = this.data.length + 3;
      }

      ServerName(HandshakeInStream var1) throws IOException {
         this.type = var1.getInt8();
         this.data = var1.getBytes16();
         this.length = this.data.length + 3;
         if (this.type == 0) {
            this.hostname = new String(this.data, "UTF8");
         } else {
            this.hostname = null;
         }

      }

      public String toString() {
         return this.type == 0 ? "host_name: " + this.hostname : "unknown-" + this.type + ": " + Debug.toString(this.data);
      }
   }
}
