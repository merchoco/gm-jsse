package cn.gmssl.security.util;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.HashMap;

public class ManifestDigester {
   public static final String MF_MAIN_ATTRS = "Manifest-Main-Attributes";
   private byte[] rawBytes;
   private HashMap<String, ManifestDigester.Entry> entries;

   private boolean findSection(int var1, ManifestDigester.Position var2) {
      int var3 = var1;
      int var4 = this.rawBytes.length;
      int var5 = var1;
      boolean var7 = true;

      for(var2.endOfFirstLine = -1; var3 < var4; ++var3) {
         byte var8 = this.rawBytes[var3];
         switch(var8) {
         case 11:
         case 12:
         default:
            var7 = false;
            break;
         case 13:
            if (var2.endOfFirstLine == -1) {
               var2.endOfFirstLine = var3 - 1;
            }

            if (var3 < var4 && this.rawBytes[var3 + 1] == 10) {
               ++var3;
            }
         case 10:
            if (var2.endOfFirstLine == -1) {
               var2.endOfFirstLine = var3 - 1;
            }

            if (var7 || var3 == var4 - 1) {
               if (var3 == var4 - 1) {
                  var2.endOfSection = var3;
               } else {
                  var2.endOfSection = var5;
               }

               var2.startOfNext = var3 + 1;
               return true;
            }

            var5 = var3;
            var7 = true;
         }
      }

      return false;
   }

   public ManifestDigester(byte[] var1) {
      this.rawBytes = var1;
      this.entries = new HashMap();
      new ByteArrayOutputStream();
      ManifestDigester.Position var3 = new ManifestDigester.Position();
      if (this.findSection(0, var3)) {
         this.entries.put("Manifest-Main-Attributes", new ManifestDigester.Entry(0, var3.endOfSection + 1, var3.startOfNext, this.rawBytes));

         for(int var4 = var3.startOfNext; this.findSection(var4, var3); var4 = var3.startOfNext) {
            int var5 = var3.endOfFirstLine - var4 + 1;
            int var6 = var3.endOfSection - var4 + 1;
            int var7 = var3.startOfNext - var4;
            if (var5 > 6 && this.isNameAttr(var1, var4)) {
               StringBuilder var8 = new StringBuilder(var6);

               try {
                  var8.append(new String(var1, var4 + 6, var5 - 6, "UTF8"));
                  int var9 = var4 + var5;
                  if (var9 - var4 < var6) {
                     if (var1[var9] == 13) {
                        var9 += 2;
                     } else {
                        ++var9;
                     }
                  }

                  int var10;
                  int var11;
                  for(; var9 - var4 < var6 && var1[var9++] == 32; var8.append(new String(var1, var10, var11, "UTF8"))) {
                     var10 = var9;

                     while(var9 - var4 < var6 && var1[var9++] != 10) {
                        ;
                     }

                     if (var1[var9 - 1] != 10) {
                        return;
                     }

                     if (var1[var9 - 2] == 13) {
                        var11 = var9 - var10 - 2;
                     } else {
                        var11 = var9 - var10 - 1;
                     }
                  }

                  this.entries.put(var8.toString(), new ManifestDigester.Entry(var4, var6, var7, this.rawBytes));
               } catch (UnsupportedEncodingException var12) {
                  throw new IllegalStateException("UTF8 not available on platform");
               }
            }
         }

      }
   }

   private boolean isNameAttr(byte[] var1, int var2) {
      return (var1[var2] == 78 || var1[var2] == 110) && (var1[var2 + 1] == 97 || var1[var2 + 1] == 65) && (var1[var2 + 2] == 109 || var1[var2 + 2] == 77) && (var1[var2 + 3] == 101 || var1[var2 + 3] == 69) && var1[var2 + 4] == 58 && var1[var2 + 5] == 32;
   }

   public ManifestDigester.Entry get(String var1, boolean var2) {
      ManifestDigester.Entry var3 = (ManifestDigester.Entry)this.entries.get(var1);
      if (var3 != null) {
         var3.oldStyle = var2;
      }

      return var3;
   }

   public byte[] manifestDigest(MessageDigest var1) {
      var1.reset();
      var1.update(this.rawBytes, 0, this.rawBytes.length);
      return var1.digest();
   }

   public static class Entry {
      int offset;
      int length;
      int lengthWithBlankLine;
      byte[] rawBytes;
      boolean oldStyle;

      public Entry(int var1, int var2, int var3, byte[] var4) {
         this.offset = var1;
         this.length = var2;
         this.lengthWithBlankLine = var3;
         this.rawBytes = var4;
      }

      public byte[] digest(MessageDigest var1) {
         var1.reset();
         if (this.oldStyle) {
            this.doOldStyle(var1, this.rawBytes, this.offset, this.lengthWithBlankLine);
         } else {
            var1.update(this.rawBytes, this.offset, this.lengthWithBlankLine);
         }

         return var1.digest();
      }

      private void doOldStyle(MessageDigest var1, byte[] var2, int var3, int var4) {
         int var5 = var3;
         int var6 = var3;
         int var7 = var3 + var4;

         for(byte var8 = -1; var5 < var7; ++var5) {
            if (var2[var5] == 13 && var8 == 32) {
               var1.update(var2, var6, var5 - var6 - 1);
               var6 = var5;
            }

            var8 = var2[var5];
         }

         var1.update(var2, var6, var5 - var6);
      }

      public byte[] digestWorkaround(MessageDigest var1) {
         var1.reset();
         var1.update(this.rawBytes, this.offset, this.length);
         return var1.digest();
      }
   }

   static class Position {
      int endOfFirstLine;
      int endOfSection;
      int startOfNext;
   }
}
