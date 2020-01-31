package com.ysoft.security;

public final class IndexState {
    private final long lastModifiedTime;
    private final String sourceHash;

    public IndexState(long lastModifiedTime, String sourceHash) {
        this.lastModifiedTime = lastModifiedTime;
        this.sourceHash = sourceHash;
    }

    public long getLastModifiedTime() {
        return lastModifiedTime;
    }

    public String getSourceHash() {
        return sourceHash;
    }
}
