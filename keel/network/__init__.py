# Copyright (c) 2026 KeelLinux maintainers
"""The network on a running machine: a change that reverts by itself

Decision 0018 of the handbook. `apply --system` plans a network change
like any other field (keel.system.network), and the one action that
carries it out, SwitchNetwork, lands here through keel.system.effects:

- keel.network.marker keeps the pending change under /var/lib/keel/network
  and the lock that makes a change, its confirmation and its revert
  exclude each other;
- keel.network.switch takes the interface down on one file and up on
  another, and arms the timer that reverts;
- keel.network.session decides whether `keel network confirm` arrived
  over the new configuration;
- keel.network.render asks inithooks' own lib/ipconfig.sh for the file,
  so a first boot and a day two write the same file for the same spec.
"""
