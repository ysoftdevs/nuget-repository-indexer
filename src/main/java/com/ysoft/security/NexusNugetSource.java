package com.ysoft.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import static com.ysoft.security.AngelaTree.merkle;
import static com.ysoft.security.AngelaTree.merkleSorted;
import static java.nio.file.Files.walkFileTree;

public class NexusNugetSource implements NugetSource {
    private static final Logger LOGGER = LoggerFactory.getLogger(NexusNugetSource.class);
    private final List<String> paths;
    private final String serverIdentity;
    public NexusNugetSource(List<String> paths, String serverIdentity) {
        this.paths = paths;
        this.serverIdentity = serverIdentity;
    }

    @Override
    public void index(long lastModifiedTime, Indexer indexer) throws IOException {
        for (final String path : paths) {
            indexDirectory(path, lastModifiedTime, indexer);
        }
    }

    private static void indexDirectory(String searchPath, final long lastModifiedTime, final Indexer indexer) throws IOException {
        final String prefix = searchPath + (searchPath.endsWith(File.separator) ? "" : File.separator);
        walkFileTree(Paths.get(searchPath), new FileVisitor<Path>() {
            public FileVisitResult preVisitDirectory(Path path, BasicFileAttributes basicFileAttributes) throws IOException {
                return FileVisitResult.CONTINUE;
            }

            public FileVisitResult visitFile(Path path, BasicFileAttributes basicFileAttributes) throws IOException {
                // We cannot use basicFileAttributes.creationTime(), because Nexus puts old (original?) timestamp for the files if mirrored
                final FileTime fileTime;
                final Process process = new ProcessBuilder("stat", "-c", "%Z", "--", path.toString()).redirectErrorStream(true).start();
                try {
                    process.getOutputStream().close();
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                        final String firstLine = reader.readLine();
                        if (reader.readLine() != null) {
                            throw new IOException("Expected EOF");
                        }
                        process.waitFor();
                        final int exitValue = process.exitValue();
                        if (exitValue != 0) {
                            throw new IOException("Bad exit value: " + exitValue);
                        }
                        // The time is rounded. Add one second in order to err on the safe side.
                        fileTime = FileTime.from(Long.parseLong(firstLine) + 1, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        throw new IOException(e);
                    }
                } finally {
                    process.destroyForcibly(); // The process is not expected to do anything at this point…
                }
                if (fileTime.toMillis() > lastModifiedTime) {
                    if (path.getFileName().toString().toLowerCase().endsWith(".nupkg")) {
                        try {
                            return process(path);
                        } catch (SQLException e) {
                            throw new IOException(e);
                        }
                    } else {
                        LOGGER.warn("Unknown file skipped: " + path);
                        return FileVisitResult.CONTINUE;
                    }
                } else {
                    return FileVisitResult.CONTINUE;
                }
            }

            private FileVisitResult process(Path path) throws IOException, SQLException {
                if (path.toString().startsWith(prefix)) {
                    final String subpath = path.toString().substring(prefix.length());
                    if (!subpath.startsWith(".nexus" + File.separator)) {
                        final String[] components = subpath.split(Pattern.quote(File.separator));
                        final String name = components[0];
                        final String version = components[1];
                        try (InputStream in = Files.newInputStream(path)) {
                            indexer.index(in, name, version);
                        }
                    }
                    return FileVisitResult.CONTINUE;
                } else {
                    throw new IOException("The path does not start with the expected prefix: " + path);
                }
            }

            public FileVisitResult visitFileFailed(Path path, IOException e) throws IOException {
                throw e;
            }

            public FileVisitResult postVisitDirectory(Path path, IOException e) throws IOException {
                return FileVisitResult.CONTINUE;
            }
        });
    }

    @Override
    public String getHash() {
        return DatatypeConverter.printHexBinary(merkle("Nexus".getBytes(StandardCharsets.UTF_8), serverIdentity.getBytes(StandardCharsets.UTF_8), merkleSorted(paths)));
    }

    @Override
    public String toString() {
        return "NexusNugetSource{" +
                "serverIdentity='" + serverIdentity + '\'' +
                ", paths=" + paths +
                '}';
    }
}
