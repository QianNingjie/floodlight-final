package net.floodlightcontroller.sflowcollector;

import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.*;
import net.floodlightcontroller.core.types.NodePortTuple;
import org.json.JSONException;
import org.json.JSONObject;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;
import org.restlet.ext.json.JsonRepresentation;
import org.restlet.representation.Representation;
import org.restlet.resource.ClientResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;


public class SflowCollector implements IFloodlightModule, ISflowCollectionService {
	public static final String sflowRtUriPropStr = "net.floodlightcontroller.sflowcollector.SflowCollector.uri";

	private static final String ENABLED_STR = "enable";
	public static final long DEFAULT_FIRST_DELAY = 5000L; //在启动的10秒之后执行
	public static final long DEFAULT_PERIOD = 5000L; //收集周期
	protected IOFSwitchService switchService;
	protected Map<Integer, InterfaceStatistics> ifIndexIfStatMap;  // sflow中的端口和收集的数据映射，注意这里的端口并不是交换机的端口
	protected Set<ISflowListener> sflowListeners;
	protected String sFlowRTURI; // json网址
	protected long firstDelay; //定时任务的参数1
	protected long period; // 定时任务的参数2
	protected static Logger log;
	private static boolean isEnabled = false;
	protected Map<NodePortTuple,InterfaceStatistics > swStats;//交换机端口 ----- 数据
	
	// 本模块提供的服务
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(ISflowCollectionService.class); 
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>, IFloodlightService> m =
				new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
        // We are the class that implements the service
        m.put(ISflowCollectionService.class, this);
        return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IOFSwitchService.class); // the service we need to depend on
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) //初始化
			throws FloodlightModuleException {
	    switchService = context.getServiceImpl(IOFSwitchService.class);
		sflowListeners = new CopyOnWriteArraySet<ISflowListener>(); // 参考http://ifeve.com/tag/copyonwritearrayset/
		ifIndexIfStatMap = new ConcurrentHashMap<Integer, InterfaceStatistics>(); // 参考  http://www.iteye.com/topic/1103980	
		swStats = new ConcurrentHashMap<NodePortTuple,InterfaceStatistics >();
		// 上述三个容器用Concurrent都是为了并发操作的线程安全
		log = LoggerFactory.getLogger(SflowCollector.class);

		Map<String, String> config = context.getConfigParams(this);
		if (config.containsKey(ENABLED_STR)) {
			try {
				isEnabled = Boolean.parseBoolean(config.get(ENABLED_STR).trim());
			} catch (Exception e) {
				log.error("Could not parse '{}'. Using default of {}", ENABLED_STR, isEnabled);
			}
		}
		log.info("SflowCollector_old {}", isEnabled ? "enabled" : "disabled");
	}

	@Override
	public void startUp(FloodlightModuleContext context) {  //模块启动
		if(!isEnabled)
			return;


		Properties prop = new Properties(); //java 配置属性文件
		InputStream is = this.getClass().getClassLoader().
                getResourceAsStream(FloodlightModuleLoader.COMPILED_CONF_FILE);//从属性文件floodlightdefault.properties读入模块配置属性
		try {
			prop.load(is);
		} catch (IOException e) {
		//.error("Could not load sFlow-RT URI configuration file", e);
			System.exit(1);
		}

		sFlowRTURI = prop.getProperty(sflowRtUriPropStr);//得到sflow-rt的Uniform Resource Identifier
		if(sFlowRTURI == null || sFlowRTURI.length() == 0) {
			System.err.println("Could not load sFlow-RT URI configuration file");
			System.exit(1);
		}else{
//			System.out.println(sFlowRTURI);
		}
		//设置收集任务的参数
		firstDelay = DEFAULT_FIRST_DELAY;
		period = DEFAULT_PERIOD; 

		Timer t = new Timer("SflowCollectionTimer"); //定义定时任务
		t.schedule(new SflowCollectTimerTask(), firstDelay, period); //在任务启动firstDelay ms之后以period的周期进行调度
		// 参考 http://www.yiibai.com/java/util/timer_schedule_period.html		
	}
	
	private void sflowCollect(String uri) {
		// 根据uri得到资源     org.restlet.jar
		ClientResource resource = new ClientResource(uri);
		//restlet  建立REST概念与Java类之间的映射
		// 例子参考  http://blog.csdn.net/is_zhoufeng/article/details/9719783
		
    	Representation r = resource.get();//得到资源的表达
		
		JsonRepresentation jr = null;
		JSONObject jo = null;
		try {
			jr = new JsonRepresentation(r);
			jo = jr.getJsonObject(); //由json的表达得到json对象
			// JSON(JavaScript Object Notation) 是一种数据交换格式
		} catch (IOException e) {
			
		} catch (JSONException e) {
			
		}
		if(jo == null) {
			System.err.println("Get JSON failed.");
		}
		
		//记录对应agentIp的switch数据
		TreeMap<Integer,InterfaceStatistics> switchdata = new TreeMap<Integer,InterfaceStatistics>();			
		@SuppressWarnings("unchecked")
		Iterator<String> it = jo.keys();
		while(it.hasNext()) {
			String key = it.next();	// key 对应	eg："3.ifadminstatus"	
			String statProp = key.substring(key.indexOf(".") + 1);	// statProp 对应	ifadminstatus
			if(InterfaceStatistics.ALLJSONPROPERTIES.contains(statProp)) {
				Integer ifIndex = -1;
				try {
					ifIndex = Integer.parseInt(key.substring(0, key.indexOf("."))); //ifIndex对应3
					
				} catch(NumberFormatException e) {
					continue;
				}
				
				if (ifIndex >= 0) {
					if (!ifIndexIfStatMap.containsKey(ifIndex)) {
						ifIndexIfStatMap.put(ifIndex, new InterfaceStatistics(ifIndex));
					}
					InterfaceStatistics is = ifIndexIfStatMap.get(ifIndex);	
					//从Json数据的key，从jo得到对应的value值，建立InterfaceStatistics对象	
					is.fromJsonProp(key, jo); 						
					switchdata.put(ifIndex, is);
				}
				else {
					System.err.println("------cannot get ifIndex from sflowdata");
				}				
			}
		}

		for(Map.Entry<Integer,InterfaceStatistics> entry : switchdata.entrySet()){
			InterfaceStatistics is = entry.getValue();
			String name = is.getIfName();
			if(name == null) return;
			int _index = name.indexOf('-');
			if(name.charAt(0) == 's' && _index != -1){
				int d = Integer.valueOf(name.substring(1,_index));
				int p = Integer.valueOf(name.substring(_index + 4));
				DatapathId dpid = DatapathId.of(d);
				OFPort port = OFPort.of(p);
				NodePortTuple npt = new NodePortTuple(dpid, port);
				swStats.put(npt, is);
			}
		}
		


	}
		
	@Override
	public void addSflowListener(ISflowListener listener) {
		sflowListeners.add(listener);
	}
	
	@Override
	public void removeSflowListener(ISflowListener listener) {
		sflowListeners.remove(listener);
	}
	
	@Override
	public Map<NodePortTuple,InterfaceStatistics > getStatisticsMap(){
		return Collections.unmodifiableMap(swStats);
	}

	private class SflowCollectTimerTask extends TimerTask {
		@Override
		public void run() {
//			swStats.clear();
	
			sflowCollect(sFlowRTURI);
			    
			// listener
			try{
				for(ISflowListener sflowListener : sflowListeners)
					sflowListener.sflowCollected(ifIndexIfStatMap) ;
			}
			catch(IOException e){
				System.out.println(e);
			}
				

//			System.out.println("sFlow Collector Stats switch bandwidth Rx BitsPerSecond");
//			for(NodePortTuple npt:swStats.keySet())
//			    log.info("{} ---{}",npt,swStats.get(npt).getIfOutOctets()*8);

		}
	}
}
