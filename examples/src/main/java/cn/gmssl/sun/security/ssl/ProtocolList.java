package cn.gmssl.sun.security.ssl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

final class ProtocolList {
   private final ArrayList<ProtocolVersion> protocols;
   private String[] protocolNames;
   final ProtocolVersion min;
   final ProtocolVersion max;
   final ProtocolVersion helloVersion;

   ProtocolList(String[] var1) {
      this(convert(var1));
   }

   ProtocolList(ArrayList<ProtocolVersion> var1) {
      this.protocols = var1;
      if (this.protocols.size() == 1 && this.protocols.contains(ProtocolVersion.SSL20Hello)) {
         throw new IllegalArgumentException("SSLv2Hello cannot be enabled unless at least one other supported version is also enabled.");
      } else {
         if (this.protocols.size() != 0) {
            Collections.sort(this.protocols);
            this.min = (ProtocolVersion)this.protocols.get(0);
            this.max = (ProtocolVersion)this.protocols.get(this.protocols.size() - 1);
            this.helloVersion = (ProtocolVersion)this.protocols.get(0);
         } else {
            this.min = ProtocolVersion.NONE;
            this.max = ProtocolVersion.NONE;
            this.helloVersion = ProtocolVersion.NONE;
         }

      }
   }

   private static ArrayList<ProtocolVersion> convert(String[] var0) {
      if (var0 == null) {
         throw new IllegalArgumentException("Protocols may not be null");
      } else {
         ArrayList var1 = new ArrayList(3);

         for(int var2 = 0; var2 < var0.length; ++var2) {
            ProtocolVersion var3 = ProtocolVersion.valueOf(var0[var2]);
            if (!var1.contains(var3)) {
               var1.add(var3);
            }
         }

         return var1;
      }
   }

   boolean contains(ProtocolVersion var1) {
      return var1 == ProtocolVersion.SSL20Hello ? false : this.protocols.contains(var1);
   }

   Collection<ProtocolVersion> collection() {
      return this.protocols;
   }

   ProtocolVersion selectProtocolVersion(ProtocolVersion var1) {
      ProtocolVersion var2 = null;
      Iterator var4 = this.protocols.iterator();

      while(var4.hasNext()) {
         ProtocolVersion var3 = (ProtocolVersion)var4.next();
         if (var1.major == 1) {
            if (var3.major == 1) {
               if (var1.minor == 0 && var3.minor == 0 || var1.minor == 1 && var3.minor == 1) {
                  var2 = var3;
                  break;
               }

               var3 = null;
            }
         } else {
            if (var3.major == 1) {
               continue;
            }

            if (var3.v > var1.v) {
               break;
            }
         }

         var2 = var3;
      }

      return var2;
   }

   synchronized String[] toStringArray() {
      if (this.protocolNames == null) {
         this.protocolNames = new String[this.protocols.size()];
         int var1 = 0;

         ProtocolVersion var2;
         for(Iterator var3 = this.protocols.iterator(); var3.hasNext(); this.protocolNames[var1++] = var2.name) {
            var2 = (ProtocolVersion)var3.next();
         }
      }

      return (String[])this.protocolNames.clone();
   }

   public String toString() {
      return this.protocols.toString();
   }
}
