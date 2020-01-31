package com.ysoft.security;

import java.io.IOException;

public interface NugetSource {
    void index(long lastModifiedTime, Indexer indexer) throws IOException;

    String getHash();
}
