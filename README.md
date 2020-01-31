# Indexer of Nuget packages

This indexer can index Artifactory and Nexus repositories for Nuget packages. It allows you to search a Nuget package by a hash of some of its DLL file.

The indexer works in batch – it scans what it can and then exits. It tries to scan only newly added Nugets. However, it relies on having good timestamps. You can run it periodically (i.e., polling) or on some event (e.g., Artifactory webhook or inotify event with Nexus).

For Artifactory, it scans a remote server.

For Nexus, it scans repository stored on local filesystem.