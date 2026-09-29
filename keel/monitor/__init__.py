# Copyright (c) 2026 KeelLinux maintainers
"""The resource monitor of handbook decision 0021

monit watches, keel tells. The monitor section of the spec is rendered
into /etc/monit/conf.d/keel.conf by `keel spec apply --system`
(keel.system.monitor), and every alert monit raises runs `keel notify`
(keel.monitor.notify), which says what happened and what to do to every
channel the spec declares. Nothing here acts on the machine: growing a
disk is the operator's act on the host.
"""
