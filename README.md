# AngryTrainer

This is an easy to use, simple version of AngryOxide that fires one-shot attacks (one at a time) and can be used to teach people these attacks.

Hint: Open WireShark on the same interface this is running to watch the traffic.

```python
Usage: angrytrainer [OPTIONS] --interface <INTERFACE> --target <TARGET>

Options:
  -i, --interface <INTERFACE>          Interface to use
  -c, --channel <CHANNEL>              Channel to scan
  -t, --target <TARGET>                Target (MAC or SSID) to attack
  -o, --output <OUTPUT>                Optional - Output filename
  -m, --mac <MAC>                      Optional - Tx MAC for rogue-based attacks - will randomize if excluded
      --deauth-all                     Attack - Send a deauth to broadcast
      --deauth-client <DEAUTH_CLIENT>  Attack - Send a deauth to a client MAC
      --csa                            Attack - Tx MAC for rogue-based attacks - will randomize if excluded
      --anon-reassoc                   Attack - Send an Anonymous Reassociation attack to target
      --rogue                          Attack - Attack a station that is probing for this target (MUST BE SSID)
      --pmkid                          Attack - Attempt to retrieve PMKID (if available) from access point
  -h, --help                           Print help
  -V, --version                        Print version
```
