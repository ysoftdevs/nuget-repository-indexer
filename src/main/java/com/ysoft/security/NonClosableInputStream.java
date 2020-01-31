package com.ysoft.security;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class NonClosableInputStream extends FilterInputStream {
    public NonClosableInputStream(InputStream input) {
        super(input);
    }

    @Override
    public void close() throws IOException {
        // ignore
    }
}
