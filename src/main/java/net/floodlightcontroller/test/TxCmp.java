package net.floodlightcontroller.test;

import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.types.NodePortTuple;
import net.floodlightcontroller.sflowcollector.ISflowCollectionService;
import net.floodlightcontroller.sflowcollector.InterfaceStatistics;
import net.floodlightcontroller.statistics.IStatisticsService;
import net.floodlightcontroller.statistics.SwitchPortBandwidth;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import org.projectfloodlight.openflow.types.OFPort;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Created by ningjieqian on 17/7/26.
 */
public class TxCmp implements IFloodlightModule {
    private IThreadPoolService threadPoolService;
    private ISflowCollectionService sflowCollectionService;
    private IStatisticsService statisticsService;
    private Map<NodePortTuple, List<Integer>> txMap1;
    private Map<NodePortTuple, List<Integer>> txMap2;

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
        l.add(IStatisticsService.class);
        l.add(ISflowCollectionService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        threadPoolService = context.getServiceImpl(IThreadPoolService.class);
        sflowCollectionService = context.getServiceImpl(ISflowCollectionService.class);
        statisticsService = context.getServiceImpl(IStatisticsService.class);
        txMap1 = new HashMap<>();
        txMap2 = new HashMap<>();
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        System.out.println("TxCmp start");
        new Thread(new TxCollector()).start();
    }

    public class TxCollector implements Runnable{

        @Override
        public void run() {
            try{
                Thread.sleep(5000);
            }catch (InterruptedException e){
                e.printStackTrace();
            }

            Map<NodePortTuple, SwitchPortBandwidth> map;
            Map<NodePortTuple,InterfaceStatistics> map2;

            int n = 100;

            for(int i = 0; i < 5;){
                map = statisticsService.getBandwidthConsumption();
                map2 =sflowCollectionService.getStatisticsMap();

                boolean flag = true;
                if(map == null || map.size() == 0){
                    System.err.println("statistics is empty");
                    flag = false;
                }

                if(map2 == null || map2.size() == 0){
                    System.err.println("sflow is empty");
                    flag = false;
                }

                if(flag){
                    System.out.println(i + "_statistics:");

                    for(Map.Entry<NodePortTuple, SwitchPortBandwidth> entry : map.entrySet()){
                        System.out.println(entry.getKey() + " : " + entry.getValue().getBitsPerSecondTx().getValue());

                        NodePortTuple npt = entry.getKey();
                        if(npt.getPortId().equals(OFPort.LOCAL))
                            continue;

                        int tx = (int)entry.getValue().getBitsPerSecondTx().getValue();
                        if(txMap1.containsKey(npt))
                            txMap1.get(npt).add(tx);
                        else{
                            List<Integer> list = new ArrayList<>();
                            list.add(tx);
                            txMap1.put(npt, list);
                        }
                    }

                    System.out.println(i + "_sflow");

                    for(Map.Entry<NodePortTuple, InterfaceStatistics> entry : map2.entrySet()){
                        System.out.println(entry.getKey() + " : " + entry.getValue().getIfOutOctets());

                        NodePortTuple npt = entry.getKey();
                        int tx = entry.getValue().getIfOutOctets().intValue()*8;
                        if(txMap2.containsKey(npt))
                            txMap2.get(npt).add(tx);
                        else{
                            List<Integer> list = new ArrayList<>();
                            list.add(tx);
                            txMap2.put(npt, list);
                        }
                    }

                    System.out.println();

                    i++;
                }

                try{
                    Thread.sleep(5000);
                }catch (InterruptedException e){
                    e.printStackTrace();
                }

            }


            File file1 = new File("outrate/statistics.txt");
            File file2 = new File("outrate/sflow.txt");

            try(PrintWriter out1 = new PrintWriter(file1);
                PrintWriter out2 = new PrintWriter(file2)){

                for(Map.Entry<NodePortTuple, List<Integer>> entry : txMap1.entrySet()){
                    NodePortTuple key = entry.getKey();
                    List<Integer> list = entry.getValue();
                    out1.print("(" + key.getNodeId().getLong() + ", " + key.getPortId() + ")\t");
                    for(Integer tx : list)
                        out1.print(tx + "\t");

                    out1.write("\n");
                }

                for(Map.Entry<NodePortTuple, List<Integer>> entry : txMap2.entrySet()){
                    NodePortTuple key = entry.getKey();
                    List<Integer> list = entry.getValue();
                    out2.print("(" + key.getNodeId().getLong() + ", " + key.getPortId() + ")\t");
                    for(Integer tx : list)
                        out2.print(tx + "\t");
                    out2.write("\n");
                }
            }catch (IOException e){
                e.printStackTrace();
            }


//            System.out.println("dump statistics collected by StatisticsCollecter");
//            for(Map.Entry<NodePortTuple, SwitchPortBandwidth> entry : map.entrySet())
//                System.out.println(entry.getKey() + " : " + entry.getValue().getBitsPerSecondTx());

//            System.out.println("dump statistics collected by SflowCollecter");
//            for(Map.Entry<NodePortTuple, InterfaceStatistics> entry : map2.entrySet())
//                System.out.println(entry.getKey() + " : " + entry.getValue().getIfOutOctets());

        }
    }
}
