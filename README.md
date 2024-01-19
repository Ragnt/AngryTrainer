# AngryTrainer

This is an easy to use, simple version of AngryOxide that fires one-shot attacks (one at a time) and can be used to teach people these attacks.

Hint: Open WireShark on the same interface this is running to watch the traffic.

All attacks are exclusive - you can only select one.

### Help

```
Usage: angrytrainer [OPTIONS] --interface <INTERFACE> --target <TARGET>

Options:
  -i, --interface <INTERFACE>          Interface to use
  -c, --channel <CHANNEL>              Channel to scan
  -t, --target <TARGET>                Target (MAC or SSID) to attack
  -o, --output <OUTPUT>                Optional - Output filename
  -m, --mac <MAC>                      Optional - Tx MAC for rogue-based attacks - will randomize if excluded
      --deauth-all                     Attack - Send a deauth to broadcast
      --deauth-client <DEAUTH_CLIENT>  Attack - Send a deauth to a client MAC
      --deauth-code <DEAUTH_CODE>      Attack - Which Deauthenticaation Reason Code to use
      --csa                            Attack - Tx MAC for rogue-based attacks - will randomize if excluded
      --anon-reassoc                   Attack - Send an Anonymous Reassociation attack to target
      --rogue                          Attack - Attack a station that is probing for this target (MUST BE SSID)
      --pmkid                          Attack - Attempt to retrieve PMKID (if available) from access point
  -h, --help                           Print help
  -V, --version                        Print version
```

### Deauthentication Codes:

```
UnspecifiedReason = 1,
PreviousAuthenticationNoLongerValid = 2,
DeauthenticatedBecauseSTAIsLeaving = 3,
DisassociatedDueToInactivity = 4,
DisassociatedBecauseAPUnableToHandleAllSTAs = 5,
Class2FrameReceivedFromNonauthenticatedSTA = 6,
Class3FrameReceivedFromNonassociatedSTA = 7,
DisassociatedBecauseSTALeavingBSS = 8,
STARequestingReassociationNotAuthenticated = 9,
DisassociatedBecauseOfPowerCapability = 10,
DisassociatedBecauseOfSupportedChannels = 11,
InvalidInformationElement = 13,
MICFailure = 14,
FourWayHandshakeTimeout = 15,
GroupKeyHandshakeTimeout = 16,
InformationElementInFourWayHandshakeDifferent = 17,
InvalidGroupCipher = 18,
InvalidPairwiseCipher = 19,
InvalidAKMP = 20,
UnsupportedRSNInformationElementVersion = 21,
InvalidRSNInformationElementCapabilities = 22,
IEEE8021XAuthenticationFailed = 23,
CipherSuiteRejectedBecauseOfSecurityPolicy = 24,
TDLSUnreachable = 25,
TDLSUnspecifiedReason = 26,
TDLSRejected = 27,
TDLSRequestedTearDown = 28,
TDLSChannelSwitching = 30,
UnauthorizedAccessPoint = 31,
PriorAuthenticationValid = 32,
ExternalServiceRequirements = 33,
InvalidFTActionFrameCount = 34,
InvalidPMKID = 35,
InvalidMDE = 36,
InvalidFTE = 37,
SMECancelsAuthentication = 38,
PeerUnreachable = 39,
PeerDeauthenticatedForListenIntervalTooLarge = 41,
DisassociatedForReasonUnspecified = 42,
PeerDeauthenticatedForReasonUnspecified = 43,
DisassociatedForSensorStation = 44,
DisassociatedForPoorChannelConditions = 45,
DisassociatedForBSSTransitionManagement = 46,
DeauthenticatedForReasonUnspecified = 47,
SessionInformationUnavailable = 48,
DisassociatedForSCPRequestUnsuccessful = 49,
DeauthenticatedForSCPRequestUnsuccessful = 50,
```
