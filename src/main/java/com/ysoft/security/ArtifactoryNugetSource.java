package com.ysoft.security;

import org.jfrog.artifactory.client.Artifactory;
import org.jfrog.artifactory.client.ArtifactoryClientBuilder;
import org.jfrog.artifactory.client.DownloadableArtifact;
import org.jfrog.artifactory.client.model.RepoPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.List;
import java.util.NavigableSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static com.ysoft.security.AngelaTree.merkle;
import static com.ysoft.security.AngelaTree.merkleSorted;

public class ArtifactoryNugetSource implements NugetSource {
    private static final Logger LOGGER = LoggerFactory.getLogger(ArtifactoryNugetSource.class);

    private final Future<Artifactory> clientFuture;
    private final List<String> repositories;
    private final String url;
    private final NavigableSet<String> exclusions;

    public ArtifactoryNugetSource(String url, String username, String password, List<String> repositories, NavigableSet<String> exclusions) {
        this.repositories = repositories;
        this.url = url;
        this.exclusions = exclusions;
        // This takes some time, so it should be done asynchronously. I know this way is a bit risky from deadlock PoV, but the code currently runs on a different thread…
        this.clientFuture = CompletableFuture.supplyAsync(() -> ArtifactoryClientBuilder.create().
                setUrl(url).
                setUsername(username).
                setPassword(password).
                build()
        );
    }

    @Override
    public void index(long lastModifiedTime, Indexer indexer) throws IOException {
        final List<RepoPath> repoPaths = client().searches().
                artifactsCreatedSince(lastModifiedTime - 1). // Add -1 in order to make sure
                repositories(repositories.toArray(new String[0])).
                doSearch();
        for (RepoPath repoPath : repoPaths) {
            final String name = repoPath.getRepoKey() + "/" + repoPath.getItemPath();
            LOGGER.info("Got file: " + name);
            if(repoPath.getItemPath().toLowerCase().endsWith(".nupkg")) {
                if(isBlacklisted(name)){
                    LOGGER.info("Skipping {} because it is blacklisted", repoPath.getItemPath());
                }else {
                    final DownloadableArtifact downloadableArtifact = client().repository(repoPath.getRepoKey()).download(repoPath.getItemPath());
                    try (InputStream inputStream = downloadableArtifact.doDownload()) {
                        indexer.index(inputStream, null, null);
                    } catch (SQLException e) {
                        throw new IOException(e);
                    }
                }
            }else{
                LOGGER.info("Skipping {} because it does not look like a NuGet.", name);
            }
        }
    }

    private boolean isBlacklisted(String itemPath) {
        // Optimization: We could try idea from https://stackoverflow.com/a/34356411 , but it seems that the code has to be fixed first
        return exclusions.stream().anyMatch(itemPath::startsWith);
    }

    private Artifactory client() {
        try {
            return clientFuture.get();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        } catch (ExecutionException e) {
            throw new AssertionError(e);
        }
    }

    @Override
    public String getHash() {
        return DatatypeConverter.printHexBinary(merkle("Artifactory".getBytes(StandardCharsets.UTF_8), url.getBytes(StandardCharsets.UTF_8), merkleSorted(repositories), merkle(exclusions)));
    }

    @Override
    public String toString() {
        return "ArtifactoryNugetSource{" +
                "url=" + url +
                ", repositories=" + repositories +
                ", exclusions=" + exclusions +
                '}';
    }
}
