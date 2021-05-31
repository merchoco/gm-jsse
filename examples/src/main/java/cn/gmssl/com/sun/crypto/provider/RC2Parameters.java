package cn.gmssl.com.sun.crypto.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.RC2ParameterSpec;
import sun.misc.HexDumpEncoder;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

public final class RC2Parameters extends AlgorithmParametersSpi {
   private static final int[] EKB_TABLE = new int[]{189, 86, 234, 242, 162, 241, 172, 42, 176, 147, 209, 156, 27, 51, 253, 208, 48, 4, 182, 220, 125, 223, 50, 75, 247, 203, 69, 155, 49, 187, 33, 90, 65, 159, 225, 217, 74, 77, 158, 218, 160, 104, 44, 195, 39, 95, 128, 54, 62, 238, 251, 149, 26, 254, 206, 168, 52, 169, 19, 240, 166, 63, 216, 12, 120, 36, 175, 35, 82, 193, 103, 23, 245, 102, 144, 231, 232, 7, 184, 96, 72, 230, 30, 83, 243, 146, 164, 114, 140, 8, 21, 110, 134, 0, 132, 250, 244, 127, 138, 66, 25, 246, 219, 205, 20, 141, 80, 18, 186, 60, 6, 78, 236, 179, 53, 17, 161, 136, 142, 43, 148, 153, 183, 113, 116, 211, 228, 191, 58, 222, 150, 14, 188, 10, 237, 119, 252, 55, 107, 3, 121, 137, 98, 198, 215, 192, 210, 124, 106, 139, 34, 163, 91, 5, 93, 2, 117, 213, 97, 227, 24, 143, 85, 81, 173, 31, 11, 94, 133, 229, 194, 87, 99, 202, 61, 108, 180, 197, 204, 112, 178, 145, 89, 13, 71, 32, 200, 79, 88, 224, 1, 226, 22, 56, 196, 111, 59, 15, 101, 70, 190, 126, 45, 123, 130, 249, 64, 181, 29, 115, 248, 235, 38, 199, 135, 151, 37, 84, 177, 40, 170, 152, 157, 165, 100, 109, 122, 212, 16, 129, 68, 239, 73, 214, 174, 46, 221, 118, 92, 47, 167, 28, 201, 9, 105, 154, 131, 207, 41, 57, 185, 233, 76, 255, 67, 171};
   private byte[] iv;
   private int version = 0;
   private int effectiveKeySize = 0;

   protected void engineInit(AlgorithmParameterSpec var1) throws InvalidParameterSpecException {
      if (!(var1 instanceof RC2ParameterSpec)) {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      } else {
         RC2ParameterSpec var2 = (RC2ParameterSpec)var1;
         this.effectiveKeySize = var2.getEffectiveKeyBits();
         if (this.effectiveKeySize != 0) {
            if (this.effectiveKeySize < 1 || this.effectiveKeySize > 1024) {
               throw new InvalidParameterSpecException("RC2 effective key size must be between 1 and 1024 bits");
            }

            if (this.effectiveKeySize < 256) {
               this.version = EKB_TABLE[this.effectiveKeySize];
            } else {
               this.version = this.effectiveKeySize;
            }
         }

         this.iv = var2.getIV();
      }
   }

   protected void engineInit(byte[] var1) throws IOException {
      DerValue var2 = new DerValue(var1);
      if (var2.tag == 48) {
         var2.data.reset();
         this.version = var2.data.getInteger();
         if (this.version < 0 || this.version > 1024) {
            throw new IOException("RC2 parameter parsing error: version number out of legal range (0-1024): " + this.version);
         }

         if (this.version > 255) {
            this.effectiveKeySize = this.version;
         } else {
            for(int var3 = 0; var3 < EKB_TABLE.length; ++var3) {
               if (this.version == EKB_TABLE[var3]) {
                  this.effectiveKeySize = var3;
                  break;
               }
            }
         }

         this.iv = var2.data.getOctetString();
      } else {
         var2.data.reset();
         this.iv = var2.getOctetString();
         this.version = 0;
         this.effectiveKeySize = 0;
      }

      if (this.iv.length != 8) {
         throw new IOException("RC2 parameter parsing error: iv length must be 8 bits, actual: " + this.iv.length);
      } else if (var2.data.available() != 0) {
         throw new IOException("RC2 parameter parsing error: extra data");
      }
   }

   protected void engineInit(byte[] var1, String var2) throws IOException {
      this.engineInit(var1);
   }

   protected AlgorithmParameterSpec engineGetParameterSpec(Class var1) throws InvalidParameterSpecException {
      if (RC2ParameterSpec.class.isAssignableFrom(var1)) {
         return this.iv == null ? new RC2ParameterSpec(this.effectiveKeySize) : new RC2ParameterSpec(this.effectiveKeySize, this.iv);
      } else {
         throw new InvalidParameterSpecException("Inappropriate parameter specification");
      }
   }

   protected byte[] engineGetEncoded() throws IOException {
      DerOutputStream var1 = new DerOutputStream();
      DerOutputStream var2 = new DerOutputStream();
      if (this.effectiveKeySize != 0) {
         var2.putInteger(this.version);
         var2.putOctetString(this.iv);
         var1.write((byte)48, var2);
      } else {
         var1.putOctetString(this.iv);
      }

      return var1.toByteArray();
   }

   protected byte[] engineGetEncoded(String var1) throws IOException {
      return this.engineGetEncoded();
   }

   protected String engineToString() {
      String var1 = System.getProperty("line.separator");
      HexDumpEncoder var2 = new HexDumpEncoder();
      StringBuilder var3 = new StringBuilder(var1 + "    iv:" + var1 + "[" + var2.encodeBuffer(this.iv) + "]");
      if (this.version != 0) {
         var3.append(var1 + "version:" + var1 + this.version + var1);
      }

      return var3.toString();
   }
}
