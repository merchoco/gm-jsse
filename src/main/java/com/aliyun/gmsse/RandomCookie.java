package com.aliyun.gmsse;

import java.io.IOException;
import java.io.PrintStream;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public  class RandomCookie {
   byte[] random_bytes;

   RandomCookie(SecureRandom generator) {
      long temp = System.currentTimeMillis() / 1000L;
      int gmt_unix_time;
      if (temp < Integer.MAX_VALUE) {
         gmt_unix_time = (int)temp;
      } else {
         gmt_unix_time = Integer.MAX_VALUE;
      }

      this.random_bytes = new byte[32];
      generator.nextBytes(this.random_bytes);
      this.random_bytes[0] = (byte)(gmt_unix_time >> 24);
      this.random_bytes[1] = (byte)(gmt_unix_time >> 16);
      this.random_bytes[2] = (byte)(gmt_unix_time >> 8);
      this.random_bytes[3] = (byte)gmt_unix_time;
   }


   public static void main(String[] args) throws NoSuchAlgorithmException {
      RandomCookie cookie = new RandomCookie(new SecureRandom());
      cookie.print(System.out);
   }

   void print(PrintStream s) {
      int i, gmt_unix_time;

      gmt_unix_time = random_bytes[0] << 24;
      gmt_unix_time += random_bytes[1] << 16;
      gmt_unix_time += random_bytes[2] << 8;
      gmt_unix_time += random_bytes[3];

      s.print("GMT: " + gmt_unix_time + " ");
      s.print("bytes = { ");

      for (i = 4; i < 32; i++) {
         if (i != 4) {
            s.print(", ");
         }
         s.print(random_bytes[i] & 0x0ff);
      }
      s.println(" }");
   }
}
