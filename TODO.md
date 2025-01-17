
# General

- [ ] Pedantic state
- [ ] brew, apt-get, rpm, chocately (windows)
- [ ] Dynamic socket buffer sizes
- [ ] Switch to 1.4/1.5 and use maps vs hashmaps in sublist
- [ ] Sublist better at high concurrency, cache uses writelock currently
- [ ] Buffer pools/sync pools?
- [ ] IOVec pools and writev for high fanout?
- [ ] Add ability to reload config on signal
- [ ] NewSource on Rand to lower lock contention on QueueSubs, or redesign!
- [ ] Add ENV and variable support to dconf
- [ ] Modify cluster support for single message across routes between pub/sub and d-queue
- [ ] Memory limits/warnings?
- [ ] Limit number of subscriptions a client can have, total memory usage etc.
- [ ] Gossip Protocol for discovery for clustering
- [ ] Info updates contain other implicit route servers
- [ ] Multi-tenant accounts with isolation of subject space
- [ ] Add to varz, time for slow consumers, peek or total connections, memory, etc.
- [X] Better user/pass support using bcrypt etc.
- [X] SSL/TLS support
- [X] Add support for / to point to varz, connz, etc..
- [X] Support sort options for /connz via nats-top
- [X] Dropped message statistics (slow consumers)
- [X] Add current time to each monitoring endpoint
- [X] varz uptime do days and only integer secs
- [X] Place version in varz (same info sent to clients)
- [X] Place server ID/UUID in varz
- [X] nats-top equivalent, utils
- [X] Connz report routes (/routez)
- [X] Docker
- [X] Remove reliance on `ps`
- [X] Syslog support
- [X] Client support for language and version
- [X] Fix benchmarks on linux
- [X] Daemon mode? Won't fix
