package net.floodlightcontroller.test;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import org.projectfloodlight.openflow.protocol.*;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionMeter;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.meterband.OFMeterBand;
import org.projectfloodlight.openflow.protocol.meterband.OFMeterBandDrop;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.OFPort;

import java.util.*;

/**
 * Created by ningjieqian on 17/7/4.
 */
public class Meter implements IFloodlightModule {
    private IOFSwitchService switchService;

    class DropMeter {
        protected DatapathId swId; /* Switch ID */
        protected OFMeterFlags flags;      /* Meter flags */
        protected int rate,        /* Meter band drop rate */
                id,          /* Meter ID */
                burstSize;   /* Burst control rate */


        public DropMeter(DatapathId swId, int id, OFMeterFlags flags, int rate, int burst) {
            this.swId = swId;
            this.flags = flags;
            this.rate = rate;
            this.id = id;
            this.burstSize = burst;
        }

        // ...

        public void write(OFMeterModCommand cmd) {
            OFFactory meterFactory = OFFactories.getFactory(OFVersion.OF_13);
            OFMeterMod.Builder meterModBuilder = meterFactory.buildMeterMod()
                    .setMeterId(id)
                    .setCommand(cmd);

            switch(cmd) {
                case ADD:
                case MODIFY:
                     /* Create and set meter band */
                    OFMeterBandDrop.Builder bandBuilder = meterFactory.meterBands().buildDrop().setRate(rate);
                    if (this.burstSize != 0) {
                        bandBuilder = bandBuilder.setBurstSize(this.burstSize);
                    }
                    OFMeterBand band = bandBuilder.build();
                    List<OFMeterBand> bands = new ArrayList<OFMeterBand>();
                    bands.add(band);

                    /* Create meter modification message */
                    Set<OFMeterFlags>  flagSet = new HashSet<>();
                    flagSet.add(flags);
                    meterModBuilder.setMeters(bands)
                            .setFlags(flagSet)
                            .build();

                    break;
                case DELETE:;
            }

        /* Send meter modification message to switch */
            IOFSwitch sw = switchService.getSwitch(swId); /* The IOFSwitchService */
            sw.write(meterModBuilder.build());

        }
    }

    public class ApplyMeter implements Runnable{
        @Override
        public void run() {
            try{
                Thread.sleep(5000);
                DropMeter dropMeter = new DropMeter(DatapathId.of(1),1, OFMeterFlags.KBPS,1,1000);
                dropMeter.write(OFMeterModCommand.ADD);
                sendFlowMod(DatapathId.of(1));

            }catch (InterruptedException e){}

        }
    }

    public void sendFlowMod(DatapathId swId){
        List<OFInstruction> instructions = new ArrayList<OFInstruction>();

        /* Meters only supported in OpenFlow 1.3 and up --> need 1.3+ factory */
        OFFactory myOF13Factory = OFFactories.getFactory(OFVersion.OF_13);
        OFInstructionMeter meter = myOF13Factory.instructions().buildMeter()
                .setMeterId(1)
                .build();

        OFAction output = myOF13Factory.actions().buildOutput()
                .setPort(OFPort.of(2))
                .setMaxLen(0xffFFffFF)
                .build();
        List<OFAction> actions = new ArrayList<OFAction>();
        actions.add(output);

        /*
         * Regardless of the instruction order in the flow, the switch is required
         * to process the meter instruction prior to any apply actions instruction.
         */
        instructions.add(meter);
        instructions.add((OFInstruction) myOF13Factory.instructions().applyActions(actions));
        /* Flow will send matched packets to meter ID 1 and then possibly output on port 2 */

        Match.Builder mb = myOF13Factory.buildMatch();
        mb.setExact(MatchField.IN_PORT, OFPort.of(1));

        OFFlowAdd flowAdd = myOF13Factory.buildFlowAdd()
        /* set anything else you need, e.g. match */
                .setInstructions(instructions)
                .setMatch(mb.build())
                .build();


        IOFSwitch sw = switchService.getSwitch(swId); /* The IOFSwitchService */
        sw.write(flowAdd);


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
        l.add(IOFSwitchService.class);
        return l;

    }

    @Override
    public void init(FloodlightModuleContext context) throws FloodlightModuleException {
        this.switchService = context.getServiceImpl(IOFSwitchService.class);
    }

    @Override
    public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
        System.out.println("---------Meter startup-------------");
        new Thread(new ApplyMeter()).start();
    }
}
