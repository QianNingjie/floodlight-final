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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Created by ningjieqian on 17/7/26.
 */
public class TxCmp implements IFloodlightModule {
    private IThreadPoolService threadPoolService;
    private ISflowCollectionService sflowCollectionService;
    private IStatisticsService statisticsService;

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
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        System.out.println("TxCmp start");
        threadPoolService.getScheduledExecutor().scheduleAtFixedRate(new TxCollector(),10,5, TimeUnit.SECONDS);
    }

    public class TxCollector implements Runnable{

        @Override
        public void run() {
            Map<NodePortTuple, SwitchPortBandwidth> map = statisticsService.getBandwidthConsumption();
            Map<NodePortTuple,InterfaceStatistics> map2 = sflowCollectionService.getStatisticsMap();

//            System.out.println("dump statistics collected by StatisticsCollecter");
//            for(Map.Entry<NodePortTuple, SwitchPortBandwidth> entry : map.entrySet())
//                System.out.println(entry.getKey() + " : " + entry.getValue().getBitsPerSecondTx());

            System.out.println("dump statistics collected by SflowCollecter");
            for(Map.Entry<NodePortTuple, InterfaceStatistics> entry : map2.entrySet())
                System.out.println(entry.getKey() + " : " + entry.getValue().getIfOutOctets());

        }
    }
}
