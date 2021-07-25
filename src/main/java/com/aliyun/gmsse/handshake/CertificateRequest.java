package com.aliyun.gmsse.handshake;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

import com.aliyun.gmsse.record.Handshake;
import com.aliyun.gmsse.record.Handshake.Body;


public class CertificateRequest extends Handshake.Body {

    @Override
    public byte[] getBytes() throws IOException {
        return null;
    }

    @Override
    public void print(PrintStream out) {

    }

    public static Body read(InputStream input) {
        return null;
    }

}
