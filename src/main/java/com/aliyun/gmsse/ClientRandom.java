package com.aliyun.gmsse;

import java.io.*;
import java.security.SecureRandom;

/**
 * SSL随机数分为client random、server random，
 * 分别由客户端和服务器生成然后通过client hello和server hello发送给对方
 * <p>
 * 随机数（random）字段包含32字节的数据。
 * 当然，只有28字节是随机生成的；剩余的4字节包含额外的信息，受客户端时钟的影响。4个字节以Unix时间格式记录了客户端的协调世界时间（UTC）。协调世界时间是从1970年1月1日开始到当前时刻所经历的秒数，那么时间是不断的上涨的，通过前4字节填写时间方式，有效的避免了周期性的出现一样的随机数。使得“随机”更加“随机”。随机数是用来生成对称密钥的。
 * 在握手时，
 * 客户端和服务器都会提供随机数。这种随机性对每次握手都是独一无二的，在身份验证中起着举足轻重的作用。它可以防止重放攻击，并确认初始数据交换的完整性。
 */
public class ClientRandom {
    public int gmtUnixTime;
    public byte[] randomBytes = new byte[28];

    public ClientRandom(int gmtUnixTime, byte[] randomBytes) {
        this.gmtUnixTime = gmtUnixTime;
        this.randomBytes = randomBytes;
    }

    public ClientRandom(SecureRandom generator) {
        long temp = System.currentTimeMillis() / 1000L;
        if (temp < Integer.MAX_VALUE) {
            gmtUnixTime = (int) temp;
        } else {
            gmtUnixTime = Integer.MAX_VALUE;
        }
        generator.nextBytes(randomBytes);
    }

    public byte[] getBytes()  {
        ByteArrayOutputStream ba = new ByteArrayOutputStream();
        ba.write((byte) ((gmtUnixTime >> 24) & 0xFF));
        ba.write((byte) ((gmtUnixTime >> 16) & 0xFF));
        ba.write((byte) ((gmtUnixTime >> 8) & 0xFF));
        ba.write((byte) (gmtUnixTime & 0xFF));
        try {
            ba.write(randomBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return ba.toByteArray();
    }

    @Override
    public String toString() {
        StringWriter str = new StringWriter();
        PrintWriter out = new PrintWriter(str);
        out.println("struct {");
        out.println("  gmt_unix_time = " + gmtUnixTime + ";");
        out.println("  random_bytes = " + Util.hexString(randomBytes) + ";");
        out.println("} Random;");
        return str.toString();
    }

    public void print(PrintStream s) {
        s.print("GMT: " + gmtUnixTime + " ");
        s.print("bytes = { ");
        for (int i = 4; i < 32; i++) {
            if (i != 4) {
                s.print(", ");
            }
                s.print(this.getBytes()[i] & 0x0ff);
        }
        s.println(" }");
    }

}