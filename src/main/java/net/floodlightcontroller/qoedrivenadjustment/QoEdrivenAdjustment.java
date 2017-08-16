package net.floodlightcontroller.qoedrivenadjustment;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Path;
import net.floodlightcontroller.routing.PathId;
import net.floodlightcontroller.sflowcollector.ISflowCollectionService;
import net.floodlightcontroller.sflowcollector.InterfaceStatistics;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.MatchUtils;
import net.floodlightcontroller.util.OFMessageUtils;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionEnqueue;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.action.OFActionSetQueue;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class QoEdrivenAdjustment extends QoEdrivenAdjBase implements IFloodlightModule {
	private static final Logger log = LoggerFactory.getLogger(QoEdrivenAdjustment.class);
//	private static volatile boolean waitingRerange
	
	private ITopologyService topologyService;

	
	private static boolean isEnabled = false;


	private Random rand = new Random(47);
	private Set<IPv4Address> unsatClient;
    private Map<IPv4Address, Integer> unsatFtpClient;
	private static FlowRegistry flowRegistry;
	private static DatapathId serverAp = DatapathId.of("00:00:00:00:00:00:00:02");  //视频服务器所连的交换机dpid
	private static final String ENABLED_STR = "enable";
	private static final long FLOWSET_BITS = 52;
    private static final long FLOWSET_MAX = (long) (Math.pow(2, FLOWSET_BITS) - 1);

    private static final IPv4Address server = IPv4Address.of("192.168.56.12");  //视频服务器ip
    private static final TransportPort serverPort = TransportPort.of(3000);     //视频服务器端口
    private static final TransportPort serverPort2 = TransportPort.of(21);
    private static final int CAPACITY = 10_000_000;
	private static final int VIDEO_BANDWIDTH = 2500_000;



	protected void doForwardFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        OFPort srcPort = OFMessageUtils.getInPort(pi);
        DatapathId srcSw = sw.getId();
        IDevice dstDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_DST_DEVICE);
        IDevice srcDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE);

        if (dstDevice == null) {
            log.debug("Destination device unknown. Flooding packet");
            doFlood(sw, pi,cntx);
            return;
        }

        if (srcDevice == null) {
            log.error("No device entry found for source device. Is the device manager running? If so, report bug.");
            return;
        }

        /* Some physical switches partially support or do not support ARP flows */
        if (FLOOD_ALL_ARP_PACKETS && 
                IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD).getEtherType()
                == EthType.ARP) {
            log.debug("ARP flows disabled in Forwarding. Flooding ARP packet");
            doFlood(sw, pi, cntx);
            return;
        }

        /* This packet-in is from a switch in the path before its flow was installed along the path */
        if (!topologyService.isEdge(srcSw, srcPort)) {  
            log.debug("Packet destination is known, but packet was not received on an edge port (rx on {}/{}). Flooding packet", srcSw, srcPort);
            doFlood(sw, pi, cntx);
            return; 
        }   

        /* 
         * Search for the true attachment point. The true AP is
         * not an endpoint of a link. It is a switch port w/o an
         * associated link. Note this does not necessarily hold
         * true for devices that 'live' between OpenFlow islands.
         * 
         * TODO Account for the case where a device is actually
         * attached between islands (possibly on a non-OF switch
         * in between two OpenFlow switches).
         */
        SwitchPort dstAp = null;
        for (SwitchPort ap : dstDevice.getAttachmentPoints()) {
			if (topologyService.isEdge(ap.getNodeId(), ap.getPortId())) {
				dstAp = ap;
				break;
			}
		}

        /* 
         * This should only happen (perhaps) when the controller is
         * actively learning a new topology and hasn't discovered
         * all links yet, or a switch was in standalone mode and the
         * packet in question was captured in flight on the dst point
         * of a link.
         */
        if (dstAp == null) {
            log.debug("Could not locate edge attachment point for destination device {}. Flooding packet");
            doFlood(sw, pi, cntx);
            return; 
        }
		DatapathId dstSw = dstAp.getNodeId();
        OFPort dstPort = dstAp.getPortId();

        /* Validate that the source and destination are not on the same switch port */
        if (sw.getId().equals(dstAp.getNodeId()) && srcPort.equals(dstAp.getPortId())) {
        	if(srcSw.equals(DatapathId.of("00:00:00:00:00:00:00:01")) && srcPort.equals(OFPort.of(7)))
        		return;
        	log.info(srcSw.toString() + " vs " + DatapathId.of("00:00:00:00:00:00:00:02").toString() + "  "
        			+ srcPort.toString() + " vs " + OFPort.of(7).toString() );
            log.info("Both source and destination are on the same switch/port {}/{}. Dropping packet", sw.toString(), srcPort);
            return;
        }		
        
        //flag[0]:该流是否需要记录，只有tcp和udp流要被记录
        //flag[1]:该流是否是视频服务器到客户端的流
        boolean[] flag = new boolean[2];

        IPv4Address[] clientIp = new IPv4Address[1];
        Match m = createMatchFromPacket(sw, srcPort, pi, cntx, flag, clientIp);

        if(flag[1] && flowRegistry.containsMatch(m))
            return;
//        System.err.println(m);
        
        long user_fields = flowRegistry.generateFlowId(log);
        U64 cookie = AppCookie.makeCookie(QDA_APP_ID, user_fields);

		List<NodePortTuple> nptList = new ArrayList<>();
		NodePortTuple npt = new NodePortTuple(srcSw, srcPort);
		nptList.add(npt);
		List<NodePortTuple> woAp = null;
		if(!srcSw.equals(dstSw)) {
			List<Path> paths = routingEngineService.getPathsFast(srcSw, dstSw);
			int num = paths.size();
			if(num > 0)
			    woAp = paths.get(rand.nextInt(paths.size())).getPath();
			else{
			    System.err.println("unreachable");
                System.err.println(srcSw + " " + srcPort + " : " + dstSw + " " + dstPort);

			}
			if(woAp != null) nptList.addAll(woAp);
		}
		npt = new NodePortTuple(dstSw, dstPort);
		nptList.add(npt);

		PathId pathId = new PathId(srcSw, dstSw);
		Path path = new Path(pathId, nptList);


        if (!path.getPath().isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("pushRoute inPort={} route={} " +"destination={}:{}",
                        new Object[] { srcPort, path,dstAp.getNodeId(),  dstPort});
                log.debug("Creating flow rules on the route, match rule: {}", m);
            }

            pushRoute(path, m, pi, sw.getId(), cookie, flag, OFFlowModCommand.ADD);
            
            //This is done after we push the path as it is blocking.
            if(woAp == null || !flag[0])
            	return;

            flowRegistry.register(cookie, m, path, woAp, flag[1] ? 0 : 1, clientIp);

            if(flag[1]){
                System.err.println("vip flow registry cookie = " + cookie + ", match = " + m);
                System.err.println("choose path " + nptList);
            }
        } 
    }


    protected Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, OFPacketIn pi, FloodlightContext cntx, boolean[] flag, IPv4Address[] clinetIp) {
        // The packet in match will only contain the port number.
        // We need to add in specifics for the hosts we're routing between.
        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
        VlanVid vlan = null;
        if (pi.getVersion().compareTo(OFVersion.OF_11) > 0 && /* 1.0 and 1.1 do not have a match */
                pi.getMatch().get(MatchField.VLAN_VID) != null) {
            vlan = pi.getMatch().get(MatchField.VLAN_VID).getVlanVid(); /* VLAN may have been popped by switch */
        }
        if (vlan == null) {
            vlan = VlanVid.ofVlan(eth.getVlanID()); /* VLAN might still be in packet */
        }
        
        MacAddress srcMac = eth.getSourceMACAddress();
        MacAddress dstMac = eth.getDestinationMACAddress();

        Match.Builder mb = sw.getOFFactory().buildMatch();
        if (FLOWMOD_DEFAULT_MATCH_IN_PORT) {
            mb.setExact(MatchField.IN_PORT, inPort);
        }

        if (FLOWMOD_DEFAULT_MATCH_MAC) {
            if (FLOWMOD_DEFAULT_MATCH_MAC_SRC) {
                mb.setExact(MatchField.ETH_SRC, srcMac);
            }
            if (FLOWMOD_DEFAULT_MATCH_MAC_DST) {
                mb.setExact(MatchField.ETH_DST, dstMac);
            }
        }

        if (FLOWMOD_DEFAULT_MATCH_VLAN) {
            if (!vlan.equals(VlanVid.ZERO)) {
                mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
            }
        }

        // TODO Detect switch type and match to create hardware-implemented flow
        if (eth.getEtherType() == EthType.IPv4) { /* shallow check for equality is okay for EthType */
            IPv4 ip = (IPv4) eth.getPayload();
            IPv4Address srcIp = ip.getSourceAddress();
            IPv4Address dstIp = ip.getDestinationAddress();

            if (FLOWMOD_DEFAULT_MATCH_IP) {
                mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
                if (FLOWMOD_DEFAULT_MATCH_IP_SRC) {
                    mb.setExact(MatchField.IPV4_SRC, srcIp);
                }
                if (FLOWMOD_DEFAULT_MATCH_IP_DST) {
                    mb.setExact(MatchField.IPV4_DST, dstIp);
                }
            }

            if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
                /*
                 * Take care of the ethertype if not included earlier,
                 * since it's a prerequisite for transport ports.
                 */
            	
                if (!FLOWMOD_DEFAULT_MATCH_IP) {
                    mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
                }

                //只有tcp和udp流记录为背景流，其他如arp等会很快就离开网络
                if (ip.getProtocol().equals(IpProtocol.TCP)) {
					flag[0] = true;
                    TCP tcp = (TCP) ip.getPayload();
                    mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP);

                    //视频服务器到客户端的流标记为vip流，并记下客户端ip用于接收到来自客户端对QoE的抱怨后，找到对应的vip流记录
                    if(srcIp.equals(server) && (tcp.getSourcePort().equals(serverPort) || tcp.getSourcePort().equals(serverPort2))){
                    	flag[1] =true;
                    	mb.setExact(MatchField.TCP_SRC, tcp.getSourcePort());
                        clinetIp[0] = dstIp;
                    } else{
                    	if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_SRC)
                    		mb.setExact(MatchField.TCP_SRC, tcp.getSourcePort());
                    	if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_DST) 
                    		mb.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
                    }
                    /*
                    if(
                    sw.getSwitchDescription().getHardwareDescription().toLowerCase().contains("open vswitch") && (
                    Integer.parseInt(sw.getSwitchDescription().getSoftwareDescription().toLowerCase().split("\\.")[0]) > 2  || (
                    Integer.parseInt(sw.getSwitchDescription().getSoftwareDescription().toLowerCase().split("\\.")[0]) == 2 &&
                    Integer.parseInt(sw.getSwitchDescription().getSoftwareDescription().toLowerCase().split("\\.")[1]) >= 1 ))
                    ){
	                    if(FLOWMOD_DEFAULT_MATCH_TCP_FLAG){
	                        mb.setExact(MatchField.OVS_TCP_FLAGS, U16.of(tcp.getFlags()));
	                    }
                    }
                    */
                } else if (ip.getProtocol().equals(IpProtocol.UDP)) {
                	flag[0] = true;
                    UDP udp = (UDP) ip.getPayload();
                    mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
                    if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_SRC) {
                        mb.setExact(MatchField.UDP_SRC, udp.getSourcePort());
                    }
                    if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_DST) {
                        mb.setExact(MatchField.UDP_DST, udp.getDestinationPort());
                    }
                }
            }
        } else if (eth.getEtherType() == EthType.ARP) { /* shallow check for equality is okay for EthType */
            mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
        } else if (eth.getEtherType() == EthType.IPv6) {
            IPv6 ip = (IPv6) eth.getPayload();
            IPv6Address srcIp = ip.getSourceAddress();
            IPv6Address dstIp = ip.getDestinationAddress();

            if (FLOWMOD_DEFAULT_MATCH_IP) {
                mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
                if (FLOWMOD_DEFAULT_MATCH_IP_SRC) {
                    mb.setExact(MatchField.IPV6_SRC, srcIp);
                }
                if (FLOWMOD_DEFAULT_MATCH_IP_DST) {
                    mb.setExact(MatchField.IPV6_DST, dstIp);
                }
            }

            if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
                /*
                 * Take care of the ethertype if not included earlier,
                 * since it's a prerequisite for transport ports.
                 */
                if (!FLOWMOD_DEFAULT_MATCH_IP) {
                    mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
                }

                if (ip.getNextHeader().equals(IpProtocol.TCP)) {
                    TCP tcp = (TCP) ip.getPayload();
                    mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP);
                    if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_SRC) {
                        mb.setExact(MatchField.TCP_SRC, tcp.getSourcePort());
                    }
                    if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_DST) {
                        mb.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
                    }
                    if(
                    sw.getSwitchDescription().getHardwareDescription().toLowerCase().contains("open vswitch") && (
                    Integer.parseInt(sw.getSwitchDescription().getSoftwareDescription().toLowerCase().split("\\.")[0]) > 2  || (
                    Integer.parseInt(sw.getSwitchDescription().getSoftwareDescription().toLowerCase().split("\\.")[0]) == 2 &&
                    Integer.parseInt(sw.getSwitchDescription().getSoftwareDescription().toLowerCase().split("\\.")[1]) >= 1 ))
                    ){
	                    if(FLOWMOD_DEFAULT_MATCH_TCP_FLAG){
	                        mb.setExact(MatchField.OVS_TCP_FLAGS, U16.of(tcp.getFlags()));
	                    }
                    }
                } else if (ip.getNextHeader().equals(IpProtocol.UDP)) {
                    UDP udp = (UDP) ip.getPayload();
                    mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
                    if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_SRC) {
                        mb.setExact(MatchField.UDP_SRC, udp.getSourcePort());
                    }
                    if (FLOWMOD_DEFAULT_MATCH_TRANSPORT_DST) {
                        mb.setExact(MatchField.UDP_DST, udp.getDestinationPort());
                    }
                }
            }
        }
        return mb.build();
    }

	protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
        OFPort inPort = OFMessageUtils.getInPort(pi);
        OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
        List<OFAction> actions = new ArrayList<OFAction>();
        Set<OFPort> broadcastPorts = this.topologyService.getSwitchBroadcastPorts(sw.getId());

        if (broadcastPorts.isEmpty()) {
            log.debug("No broadcast ports found. Using FLOOD output action");
            broadcastPorts = Collections.singleton(OFPort.FLOOD);
        }

        for (OFPort p : broadcastPorts) {
            if (p.equals(inPort)) continue;
            actions.add(sw.getOFFactory().actions().output(p, Integer.MAX_VALUE));
        }
        pob.setActions(actions);
        
        // set buffer-id, in-port and packet-data based on packet-in
        pob.setBufferId(OFBufferId.NO_BUFFER);
        OFMessageUtils.setInPort(pob, inPort);
        pob.setData(pi.getData());

        if (log.isTraceEnabled()) {
            log.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
                    new Object[] {sw, pi, pob.build()});
        }
        messageDamper.write(sw, pob.build());

        return;
    }
	 
	@Override
	public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi,
                                          FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		if (eth.isBroadcast() || eth.isMulticast()) 
	            doFlood(sw, pi, cntx);
	    else 
	    	doForwardFlow(sw, pi, cntx);
		return Command.CONTINUE;
	}	
	
	@Override
	public Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved flowRemovedMessage) {
		U64 cookie = flowRemovedMessage.getCookie();
		if(AppCookie.extractApp(cookie) != QDA_APP_ID){
			return Command.CONTINUE;
		}
		
//		log.info("{} flow entry removed {}", sw, flowRemovedMessage);
		
		//流表删除理由为DELETE，是重路由时主动删除的，重路由后即完成对流记录的更新
        OFFlowRemovedReason removedReason = flowRemovedMessage.getReason();
		if(removedReason.equals(OFFlowRemovedReason.DELETE))
			return Command.CONTINUE;

        //正常离开网络的流，包括普通流和vip流
		flowRegistry.removeExpiredFlow(cookie, removedReason);
		
		return Command.CONTINUE;
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IThreadPoolService.class);
		l.add(ITopologyService.class);
		l.add(ISflowCollectionService.class);
		l.add(IStatisticsService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		super.init();
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceManagerService = context.getServiceImpl(IDeviceService.class);
        this.routingEngineService = context.getServiceImpl(IRoutingService.class);
        this.switchService = context.getServiceImpl(IOFSwitchService.class);
		this.sflowCollectionService = context.getServiceImpl(ISflowCollectionService.class);
		this.statisticsService = context.getServiceImpl(IStatisticsService.class);
		this.threadPoolService = context.getServiceImpl(IThreadPoolService.class);

		flowRegistry = FlowRegistry.getInstance();
		unsatClient = Collections.synchronizedSet(new HashSet<>());
        unsatFtpClient = new ConcurrentHashMap<>();

		Map<String, String> config = context.getConfigParams(this);
		if (config.containsKey(ENABLED_STR)) {
			try {
				isEnabled = Boolean.parseBoolean(config.get(ENABLED_STR).trim());
			} catch (Exception e) {
				log.error("Could not parse '{}'. Using default of {}", ENABLED_STR, isEnabled);
			}
		}
		log.info("QoE-driven Adjustment {}", isEnabled ? "enabled" : "disabled");
		
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		if(isEnabled){
			super.startUp();


			new Thread(new ComplainCollector(unsatClient)).start();
            new Thread(new FTPComplainCollector(unsatFtpClient)).start();
			threadPoolService.getScheduledExecutor().scheduleAtFixedRate(new Adjustment(),10,5, TimeUnit.SECONDS);

		}

	}


    public static volatile int tag = 0;

	private void adjFtp(){
        System.err.println("adjust for FTP");

        Map<DatapathId, Set<Link>> dpidToLinks = topologyService.getAllLinks();
        int n = dpidToLinks.keySet().size();
        if(n == 0){
            log.info("empty topo ---- unreliable topology module");
            return;
        }

        Set<Link> links = new HashSet<>();
        for(Set<Link> set : dpidToLinks.values())
            links.addAll(set);

        Map<NodePortTuple,InterfaceStatistics> statisticsMap = sflowCollectionService.getStatisticsMap();
//        Map<NodePortTuple, SwitchPortBandwidth> statisticsMap = statisticsService.getBandwidthConsumption();

        if(statisticsMap == null || statisticsMap.size() == 0)
            System.err.println("SflowCollector/StatisticsCollector doesn't open");

        Map<Link, Integer> linkIdle = new HashMap<>();  //链路剩余带宽
        Map<Link, Integer> linkBg = new HashMap<>();    //背景流占用的带宽（限速的上限）
        Map<Link, Integer> linkConsume = new HashMap<>(); //链路已占用带宽



        for(Link link : links){
            NodePortTuple npt = new NodePortTuple(link.getSrc(),link.getSrcPort());
            int outRate = 0;
            if(statisticsMap.containsKey(npt)){
//                outRate = (int)statisticsMap.get(npt).getBitsPerSecondTx().getValue();
                outRate = (int)statisticsMap.get(npt).getIfOutOctets().doubleValue() * 8 ;
                linkConsume.put(link, outRate);
            }

            linkIdle.put(link, CAPACITY - outRate);
        }



        Map<Link, Integer> linkLimit = new HashMap<>();
        for(IPv4Address ip : unsatFtpClient.keySet()){
            int limit = unsatFtpClient.get(ip);

            System.out.println("complain from FTP client" + ip);
            U64 cookie = flowRegistry.getCookie(ip);
            if(cookie == null){
                System.err.println("can't get client cookie");
                return;
            }

            List<NodePortTuple> path = flowRegistry.getOldPath(cookie);
            for(int i = 1; i < path.size()-2; i += 2){
                NodePortTuple npt1 = path.get(i);
                NodePortTuple npt2 = path.get(i+1);
                Link link = new Link(npt1.getNodeId(),npt1.getPortId(), npt2.getNodeId(), npt2.getPortId(), U64.ZERO);
                linkLimit.put(link, limit * 1000_000);
            }

        }

//        System.err.println("linkLimit = " + linkLimit);

        Map<U64, Integer> cki2limit = new HashMap<>();
        for(Map.Entry<Link, Integer> entry : linkLimit.entrySet()){
            if(entry.getValue() != 0) {
                Set<U64> cki = flowRegistry.getBgCki(entry.getKey());
                if(cki != null)
                    for(U64 k : cki)
                        if(cki2limit.containsKey(k)){
                            int max =  Math.max(entry.getValue(), cki2limit.get(k));
                            cki2limit.put(k, max);
                        }else{
                            cki2limit.put(k, entry.getValue());
                        }
            }
        }

        for(Map.Entry<U64, Integer> entry : cki2limit.entrySet()){
            U64 cookie = entry.getKey();
            Match match = flowRegistry.getMatch(cookie);
            int limit = entry.getValue();
            System.err.println(match + ", ");
//            System.err.println("cookie = " + cookie);


            List<NodePortTuple> switchPortList = flowRegistry.getOldPath(cookie);
            for (int indx = switchPortList.size() - 1; indx > 0; indx -= 2) {
                DatapathId switchDPID = switchPortList.get(indx).getNodeId();
                IOFSwitch sw = switchService.getSwitch(switchDPID);
                OFPort outPort = switchPortList.get(indx).getPortId();
                OFPort inPort = switchPortList.get(indx - 1).getPortId();

                long queueId = getCorrespondingQueueId(outPort, limit);

                OFFactory myfactory = sw.getOFFactory();
                OFFlowMod.Builder fmb = myfactory.buildFlowAdd();

                ArrayList<OFAction> actionsLinkSrcPort = new ArrayList<OFAction>();

                    /* For OpenFlow 1.0 */
                if (myfactory.getVersion().compareTo(OFVersion.OF_10) == 0) {
                    OFActionEnqueue enqueue = myfactory.actions().buildEnqueue()
                            .setPort(outPort) /* Must specify port number */
                            .setQueueId(queueId)
                            .build();
                    actionsLinkSrcPort.add(enqueue);

                } else { /* For OpenFlow 1.1+ */
                    OFActionSetQueue setQueue = myfactory.actions().buildSetQueue()
                            .setQueueId(queueId)
                            .build();
                    actionsLinkSrcPort.add(setQueue);
                    actionsLinkSrcPort.add(myfactory.actions().buildOutput().setPort(outPort).build());
                }

                //
                U64 cookieMask =  U64.NO_MASK;
                //删除相应Match的流表
                if(myfactory.getVersion().compareTo(OFVersion.OF_10) == 0)
                    System.err.println("to add...");
                else
                    sw.write(myfactory.buildFlowDelete().setCookie(cookie).setCookieMask(cookieMask).build());
                //下发相应Match的流表

                Match.Builder mb = MatchUtils.convertToVersion(match, sw.getOFFactory().getVersion());
                mb.setExact(MatchField.IN_PORT, inPort);

                sw.write(fmb.setBufferId(OFBufferId.NO_BUFFER)
                        .setActions(actionsLinkSrcPort)
                        .setIdleTimeout(60)
                        .setMatch(mb.build())
                        .setCookie(cookie)
                        .setOutPort(outPort)
                        .setPriority(32676).build());

            }
            System.err.println("enqueue");


        }

        unsatFtpClient.clear();
        System.err.println("adjust done");

    }

    private class Adjustment implements Runnable{
        @Override
        public void run() {
//            Map<NodePortTuple,InterfaceStatistics> map = sflowCollectionService.getStatisticsMap();
//            System.out.println("dump statistics collected by SflowCollecter");
//            for(Map.Entry<NodePortTuple, InterfaceStatistics> entry : map.entrySet())
//                System.out.println(entry.getKey() + " : " + entry.getValue().getIfOutOctets()*8);

            if(!unsatFtpClient.isEmpty())
                adjFtp();

            if(unsatClient.isEmpty())
                return;

            System.err.println(unsatClient);

            System.err.println("adjust for video");

            Map<DatapathId, Set<Link>> dpidToLinks = topologyService.getAllLinks();
            int n = dpidToLinks.keySet().size();
            if(n == 0){
                log.info("empty topo ---- unreliable topology module");
                return;
            }

            Set<Link> links = new HashSet<>();
            for(Set<Link> set : dpidToLinks.values())
                links.addAll(set);

            Map<NodePortTuple,InterfaceStatistics> statisticsMap = sflowCollectionService.getStatisticsMap();
//            Map<NodePortTuple, SwitchPortBandwidth> statisticsMap = statisticsService.getBandwidthConsumption();

            if(statisticsMap == null || statisticsMap.size() == 0)
                System.err.println("SflowCollector/StatisticsCollector doesn't open");

            Map<Link, Integer> linkIdle = new HashMap<>();  //链路剩余带宽
            Map<Link, Integer> linkBg = new HashMap<>();    //背景流占用的带宽（限速的上限）
            Map<Link, Integer> linkConsume = new HashMap<>(); //链路已占用带宽

            for(Link link : links){
                NodePortTuple npt = new NodePortTuple(link.getSrc(),link.getSrcPort());
                int outRate = 0;
                if(statisticsMap.containsKey(npt)){
//                    outRate = (int)statisticsMap.get(npt).getBitsPerSecondTx().getValue();
                    outRate = (int)statisticsMap.get(npt).getIfOutOctets().doubleValue() * 8 ;
//                    System.out.println(link + " --- " + outRate);
                    linkConsume.put(link, outRate);
                }


                linkIdle.put(link, CAPACITY - outRate);

                int cnt = flowRegistry.getNumOfVip(link);

                if(cnt > 1 || cnt < 0){
                    System.err.println("cnt = " + cnt);
                    System.err.println(link);
                    Set<U64> ckis= flowRegistry.linkToFlow.get(link)[0];
                    for(U64 cki : ckis)
                        System.err.println(cki + " ---- " + flowRegistry.flowMatch.get(cki));
                    System.err.println();

                }

                linkBg.put(link, outRate - VIDEO_BANDWIDTH * cnt);
            }


            int flowSrc = (int)serverAp.getLong();

            List<Integer> flowDst = new ArrayList<>();

            for(IPv4Address ip : unsatClient){
                System.out.println("complain from video client " + ip);
                U64 cookie = flowRegistry.getCookie(ip);
                if(cookie == null){
                    System.err.println("can't get client cookie");
                    return;
                }

                int dst = flowRegistry.getClientAp(cookie);
                if(dst == -1){
                    System.err.println("can't locate client.");
                    return;
                }
                else
                    flowDst.add(dst);
            }

//            System.err.println(flowSrc + " -> " + flowDst);

            int threshold = 0;
            List<List<Link>> flowPath = new ArrayList<>();
            Map<Link, Integer> linkLimit = new HashMap<>();
            boolean success = MaxFlowSolver.rearrangeFlow(links, n, linkIdle, linkBg, flowSrc, flowDst, VIDEO_BANDWIDTH, threshold, flowPath, linkLimit);
            System.err.println("rearrange success ? " + success);
            for(Link link : linkIdle.keySet()){
                System.err.print("(");
                System.err.print(link.getSrc().getLong() + ", " + link.getSrcPort() + ") - "
                        + "(" + link.getDst().getLong() + ", " + link.getDstPort() + ") "
                        + ", idle = " + linkIdle.get(link) + ", consume = " + linkConsume.get(link)  + ", bg = " + linkBg.get(link) + "\n");
            }

            System.err.println("flowPath: " + flowPath);
            System.err.println("linkLimit: " + linkLimit);


            if(flowPath.size() == 0){
                System.err.println("no available path");
                return;
            }

            int i = 0;
            for(IPv4Address ip : unsatClient){
                U64 cookie = flowRegistry.getCookie(ip);
                List<NodePortTuple> oldPath = flowRegistry.getOldPath(cookie);

                NodePortTuple first = oldPath.get(0), last = oldPath.get(oldPath.size()-1);

                List<Link> linkList = flowPath.get(i++);
                if(linkList.size()==0){
                    System.err.println("infeasible ---- " + ip);
                    continue;
                }

                List<NodePortTuple> nptList = new ArrayList<>();
                nptList.add(first);


                boolean isSame = false;
                int k = 0, r = oldPath.size() - 2;
                for(int j = 0; j < linkList.size(); j++){
                    Link link = linkList.get(j);
                    NodePortTuple npt1 = new NodePortTuple(link.getSrc(),link.getSrcPort());
                    NodePortTuple npt2 = new NodePortTuple(link.getDst(), link.getDstPort());
                    nptList.add(npt1);
                    nptList.add(npt2);
                    if(k <= r && oldPath.get(++k).equals(npt1) &&  oldPath.get(k++).equals(npt2))
                        isSame = true;
                    else
                        isSame = false;
                }

                if(r != 2 * linkList.size())
                    isSame = false;
                if(isSame)
                    System.err.println("new path is same as the old one");

                nptList.add(last);


                PathId pathId = new PathId(first.getNodeId(),last.getNodeId());
                Path path = new Path(pathId, nptList);

                boolean[] flag = new boolean[2];
                flag[0] = true;
                flag[1] = true;

                long user_fields = flowRegistry.generateFlowId(log);
                U64 newCookie = AppCookie.makeCookie(QDA_APP_ID, user_fields);
//                System.err.println(newCookie);


                boolean routePushed = pushRoute(path, flowRegistry.getMatch(cookie), null, null, newCookie, flag  , OFFlowModCommand.ADD);


                removeFlow(oldPath, cookie);


                flowRegistry.update(cookie, newCookie, oldPath, linkList, path, ip);

            }



            Map<U64, Integer> cki2limit = new HashMap<>();
            for(Map.Entry<Link, Integer> entry : linkLimit.entrySet()){
                if(entry.getValue() != 0) {
                    Set<U64> cki = flowRegistry.getBgCki(entry.getKey());
                    if(cki != null)
                        for(U64 k : cki)
                            if(cki2limit.containsKey(k)){
                                int max =  Math.max(entry.getValue(), cki2limit.get(k));
                                cki2limit.put(k, max);
                            }else{
                                cki2limit.put(k, entry.getValue());
                            }
                }
            }

            for(Map.Entry<U64, Integer> entry : cki2limit.entrySet()){
                U64 cookie = entry.getKey();
                Match match = flowRegistry.getMatch(cookie);
                int limit = entry.getValue();
                System.err.println("match = " + match);
//                System.err.println("cookie = " + cookie);


                List<NodePortTuple> switchPortList = flowRegistry.getOldPath(cookie);
                for (int indx = switchPortList.size() - 1; indx > 0; indx -= 2) {
                    DatapathId switchDPID = switchPortList.get(indx).getNodeId();
                    IOFSwitch sw = switchService.getSwitch(switchDPID);
                    OFPort outPort = switchPortList.get(indx).getPortId();
                    OFPort inPort = switchPortList.get(indx - 1).getPortId();

                    long queueId = getCorrespondingQueueId(outPort, limit);

                    OFFactory myfactory = sw.getOFFactory();
                    OFFlowMod.Builder fmb = myfactory.buildFlowAdd();

                    ArrayList<OFAction> actionsLinkSrcPort = new ArrayList<OFAction>();

                    /* For OpenFlow 1.0 */
                    if (myfactory.getVersion().compareTo(OFVersion.OF_10) == 0) {
                        OFActionEnqueue enqueue = myfactory.actions().buildEnqueue()
                                .setPort(outPort) /* Must specify port number */
                                .setQueueId(queueId)
                                .build();
                        actionsLinkSrcPort.add(enqueue);

                    } else { /* For OpenFlow 1.1+ */
                        OFActionSetQueue setQueue = myfactory.actions().buildSetQueue()
                                .setQueueId(queueId)
                                .build();
                        actionsLinkSrcPort.add(setQueue);
                        actionsLinkSrcPort.add(myfactory.actions().buildOutput().setPort(outPort).build());
                    }

                    //
                    U64 cookieMask =  U64.NO_MASK;
                    //删除相应Match的流表
                    if(myfactory.getVersion().compareTo(OFVersion.OF_10) == 0)
                        System.err.println("to add...");
                    else
                        sw.write(myfactory.buildFlowDelete().setCookie(cookie).setCookieMask(cookieMask).build());
                    //下发相应Match的流表

                    Match.Builder mb = MatchUtils.convertToVersion(match, sw.getOFFactory().getVersion());
                    mb.setExact(MatchField.IN_PORT, inPort);

                    Set<OFFlowModFlags> flags = new HashSet<>();
                    flags.add(OFFlowModFlags.SEND_FLOW_REM);


                    sw.write(fmb.setBufferId(OFBufferId.NO_BUFFER)
                            .setActions(actionsLinkSrcPort)
                            .setIdleTimeout(60)
                            .setMatch(mb.build())
                            .setCookie(cookie)
                            .setOutPort(outPort)
                            .setPriority(32676)
                            .setFlags(flags).build());

                }
                System.err.println("enqueue");


            }


            unsatClient.clear();
            System.err.println("adjust done");
        }


    }

    private TableId getMatchTableId(Match m){
        //table id max 255
        IPv4Address srcIp = m.get(MatchField.IPV4_SRC);
        IPv4Address dstIp = m.get(MatchField.IPV4_DST);
        TransportPort dstPort =  m.get(MatchField.TCP_DST);
        TransportPort srcPort = m.get(MatchField.TCP_SRC);
        int big = 314159;
        int hash = Math.abs(srcIp.getInt()) % big + Math.abs(dstIp.getInt()) % big +
                ((dstPort == null) ? 97 : dstPort.getPort())
                + ((srcPort == null) ? 31 : srcPort.getPort());
        int tmp = hash % 256;
        System.err.println(tmp);
        return TableId.of(tmp);
    }

    /*
    of10 queueid是与端口号有关的，每个端口都可以有自己的端口号
    of13 queueid是全局唯一的，所以setQueue操作只需要制定端口号
     = ofportNum * interval + bps2Id
     */
    private long getCorrespondingQueueId(OFPort opt, Integer limit){
        final int INTERVAL = 40;
        int bps2Id = (limit % 1000000 == 0) ? (limit / 1000000) : (limit / 1000000 + 1);
        int ans = opt.getPortNumber() * INTERVAL + bps2Id;
        return ans;
    }


}
