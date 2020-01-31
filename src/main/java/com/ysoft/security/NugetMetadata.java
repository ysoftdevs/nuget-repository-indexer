package com.ysoft.security;

import java.util.Map;

public class NugetMetadata {
    private final NugetIdentifier nugetIdentifier;
    private final Map<String, Map<String, String>> hashesForFiles;
    public NugetMetadata(NugetIdentifier nugetIdentifier, Map<String, Map<String, String>> hashesForFiles) {
        this.nugetIdentifier = nugetIdentifier;
        this.hashesForFiles = hashesForFiles;
    }
    public NugetIdentifier getNugetIdentifier() {
        return nugetIdentifier;
    }
    public Map<String, Map<String, String>> getHashesForFiles() {
        return hashesForFiles;
    }
}
