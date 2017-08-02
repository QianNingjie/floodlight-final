package net.floodlightcontroller.qoedrivenadjustment;

import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.linkdiscovery.Link;
import net.floodlightcontroller.routing.Path;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.IPAddress;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by ningjieqian on 17/7/9.
 */
public class FlowRegistry {
    private static final long FLOWSET_BITS = 52;
    private static final long FLOWSET_MAX = (long) (Math.pow(2, FLOWSET_BITS) - 1);

    volatile Map<U64, Path> flowToPath;
    volatile Map<Link, Set<U64>[]> linkToFlow; //0视频流 1普通流
    volatile Map<U64, Match> flowMatch;
    volatile Map<IPv4Address, U64> ipToCki; //只记录从视频服务器到客户端的流的ip到cookie的映射（反向流比较小，不需要保障带宽）

    private volatile long flowIdGenerator = -1;
    private static volatile FlowRegistry instance;

    private FlowRegistry(){
        flowToPath  = new ConcurrentHashMap<>();
        linkToFlow = new ConcurrentHashMap<>();
        flowMatch = new ConcurrentHashMap<>();
        ipToCki = new ConcurrentHashMap<>();
    }

     static FlowRegistry getInstance() {
        if (instance == null)
            instance = new FlowRegistry();
        return instance;
    }

     synchronized long generateFlowId(Logger log) {
        flowIdGenerator += 1;
        if (flowIdGenerator == FLOWSET_MAX) {
            flowIdGenerator = 0;
            log.warn("Flowset IDs have exceeded capacity of {}. Flowset ID generator resetting back to 0", FLOWSET_MAX);
        }
        log.debug("Generating flowset ID {}", flowIdGenerator);
        return flowIdGenerator;
    }

    //获取链路上的背景流的match
    Set<Match> getBgMatch(Link link){
        if(linkToFlow.containsKey(link)){
            Set<U64> ckis = linkToFlow.get(link)[1];
            Set<Match> matches = new HashSet<>();
            for(U64 cki : ckis)
                if(flowMatch.containsKey(cki))
                    matches.add(flowMatch.get(cki));
                else
                    System.err.println("cki -/> match");
            return matches;
        }else
            System.err.println("link doesn't exist");
        return null;
    }

    //获取链路上的视频流数量
    int getNumOfVip(Link link){
        if(linkToFlow.containsKey(link))
            return linkToFlow.get(link)[0].size();
        else return 0;
    }

    U64 getCookie(IPv4Address ip){
        if(ipToCki.containsKey(ip))
            return ipToCki.get(ip);
        else
            return null;
    }

    Match getMatch(U64 cookie){
        return flowMatch.get(cookie);
    }

    List<NodePortTuple> getOldPath(U64 cookie){
        return flowToPath.get(cookie).getPath();
    }

    //获取cookie对应vip流的宿主机(客户端)所连的交换机
    int getClientAp(U64 cookie){
        if(flowToPath.containsKey(cookie)){
            List<NodePortTuple> nptList = flowToPath.get(cookie).getPath();
            return (int)nptList.get(nptList.size()-1).getNodeId().getLong();
        }else return -1;
    }



    void register(U64 cookie, Match match, Path path, List<NodePortTuple> npts, int type, IPv4Address[] clientIp){
        flowMatch.put(cookie, match);
        if(clientIp[0] != null)
            ipToCki.put(clientIp[0], cookie);

        flowToPath.put(cookie, path);

        for(int i = 0; i < npts.size()-1; i++){
            NodePortTuple a = npts.get(i);
            NodePortTuple b = npts.get(i+1);
            Link link = new Link(a.getNodeId(), a.getPortId(), b.getNodeId(), b.getPortId(), U64.ZERO);
            addToLtf(link, cookie, type);
        }
    }

    private void addToLtf(Link link, U64 cookie, int type){
        if(linkToFlow.containsKey(link))
            linkToFlow.get(link)[type].add(cookie);
        else{
            Set[] tmp = new Set[2];
            tmp[0] = new HashSet<U64>();
            tmp[1] = new HashSet<U64>();
            tmp[type].add(cookie);
            linkToFlow.put(link,tmp);
        }
    }

    void update(U64 cookie, List<NodePortTuple> oldPath, List<Link> linkList, Path newPath){
        flowToPath.put(cookie, newPath);

        //remove vip flow from old links
//        System.err.println("oldPath : " + oldPath);
//        System.err.println("newPath : " + newPath);
        for(int i = 1; i < oldPath.size()-1; i += 2){
            NodePortTuple npt1 = oldPath.get(i);
            NodePortTuple npt2 = oldPath.get(i+1);
            Link link = new Link(npt1.getNodeId(),npt1.getPortId(), npt2.getNodeId(), npt2.getPortId(), U64.ZERO);
            boolean flag = false;
            if(linkToFlow.containsKey(link))
                flag = linkToFlow.get(link)[0].remove(cookie);
            else
                System.err.print(link + " disappear");

            if(!flag) throw new RuntimeException("why??");
        }

        //add new
        for(Link link :linkList)
            addToLtf(link, cookie, 0);
    }


    void removeExpiredFlow(U64 cookie){
//        System.err.println("remove " + cookie);
        flowToPath.remove(cookie);
        flowMatch.remove(cookie);
        Iterator<U64> ckis = ipToCki.values().iterator();
        while(ckis.hasNext()){
            U64 cki = ckis.next();
            if(cki.equals(cookie))
                ckis.remove();
        }

        Iterator<Set<U64>[]> it = linkToFlow.values().iterator();
        while(it.hasNext()){
            Set<U64>[] sets = it.next();
            sets[0].remove(cookie);
            sets[1].remove(cookie);
        }

    }
}