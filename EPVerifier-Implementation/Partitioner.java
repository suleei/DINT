package org.snlab.EPVerifier;

import org.checkerframework.checker.units.qual.A;
import org.jgrapht.alg.util.Pair;
import org.snlab.EPVerifier.ModelManager.BDDEngine;
import org.snlab.EPVerifier.ModelManager.IndexedRules;
import org.snlab.network.Device;
import org.snlab.network.Network;
import org.snlab.network.Rule;

import java.io.*;
import java.util.*;
class Counter{
    double memoryCounter;
    double timeCounter;
    public Counter(){

        this.timeCounter=0;
        this.memoryCounter=0;
    }

    public void addMemory(double adder){
        this.memoryCounter+=adder;
    }

    public double getMemoryCounter(){
        return this.memoryCounter;
    }

    public void addTime(double adder){
        this.timeCounter+=adder;
    }

    public double getTimeCounter(){
        return this.timeCounter;
    }
}

class Region{
    private int updateCount;
    private List<Pair<Boolean,Rule>> updateSequence;

    private Set<Device> devices;
    public Region(){
        this.updateCount=0;
        this.updateSequence=new ArrayList<>();
        this.devices = new HashSet<>();
    }

    public int getUpdateCount(){
        return this.updateCount;
    }

    public int getSequenceSize(){
        return this.updateSequence.size();
    }

    public void insertUpdate(Pair<Boolean,Rule> rulePair){
        this.updateSequence.add(rulePair);
        this.devices.add(rulePair.getSecond().getDevice());
    }

    public void insertDevice(int sequenceNum){
        this.updateCount+=sequenceNum;
    }

    public List<Pair<Boolean,Rule>> getUpdateSequence(){
        return this.updateSequence;
    }

    public Set<Device> getDevices(){
        return this.devices;
    }
}

class DeviceComparator implements Comparator<Pair<Device,Integer>>{
    public int compare(Pair<Device,Integer> a,Pair<Device,Integer> b){
        return b.getSecond()-a.getSecond();
    }
}

class RegionComparator implements Comparator<Region>{
    public int compare(Region a,Region b){
        return a.getUpdateCount()- b.getUpdateCount();
    }
}


class GlobalModel{
    private HashMap<String, Integer> M;
    private BDDEngine b;

    private double m;
    private double t;

    public GlobalModel(){
        this.b = new BDDEngine(32);
        this.M = new HashMap<>();
    }

    public void transferEP(Map<String,List<String>> deltaMap) {
        /*Runtime.getRuntime().gc();
        double memoryBefore = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        double s=-System.nanoTime();*/
        for(String link:deltaMap.keySet()){
            List<String> normalFormList = deltaMap.get(link);
            int normalFormIndex = this.b.BDDFalse;
            if(normalFormList.size()==1){
                if(normalFormList.get(0)=="FALSE"){
                    this.M.put(link,this.b.BDDFalse);
                }else if (normalFormList.get(0)=="TRUE"){
                    this.M.put(link,this.b.BDDTrue);
                }
            }else{
                for(String normalForm: normalFormList){
                    int ret = this.b.BDDTrue;
                    for(int i=0;i<32;i++){
                        if(normalForm.charAt(i)=='0'){
                            ret = this.b.and(ret, this.b.getVars()[i]);
                        }else if(normalForm.charAt(i)=='1'){
                            ret = this.b.and(ret, this.b.getnVars()[i]);
                        }
                    }
                    normalFormIndex = this.b.or(normalFormIndex, ret);
                }
                this.M.put(link,normalFormIndex);
            }
        }
        /*s+=System.nanoTime();
        double memoryAfter = Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
        double byte2MB = 1024L * 1024L;
        double ret = ((memoryAfter - memoryBefore) / byte2MB);
        this.t=s;
        this.m=ret;*/
    }

    public double getT(){
        return this.t;
    }

    public double getM(){
        return this.m;
    }
}

class EPModel extends Thread{
    private Region region;

    private HashMap<Device, IndexedRules> deviceToRules;

    private HashMap<Rule, Integer> ruleToBddForm;


    private HashMap<Device, BDDEngine> B;

    private HashMap<String, Integer> M;

    private HashMap<String, Device> linkToDevice;

    /*private Counter counter;*/

    private Map<String,List<String>> deltaMap;

    private double m;

    private double t1,t2;


    public EPModel(Region region, Map<String,List<String>> deltaMap){
        this.region=region;
        this.B = new HashMap<>();
        this.M = new HashMap<>();
        this.linkToDevice=new HashMap<>();
        this.deviceToRules=new HashMap<>();
        this.ruleToBddForm=new HashMap<>();
        for(Device device:this.region.getDevices()){
            this.deviceToRules.put(device, new IndexedRules());
            this.B.put(device, new BDDEngine(32));
        }
        this.deltaMap = deltaMap;
    }


    private int getHit(Rule rule) {
        BDDEngine bddEngine = this.B.get(rule.getDevice());
        rule.setHit(this.ruleToBddForm.get(rule));
        for(Rule r_apo: this.deviceToRules.get(rule.getDevice()).getAllOverlappingWith(rule, 32)){
            int intersection = bddEngine.and(r_apo.getHit(), rule.getHit());
            if(r_apo.getPriority() > rule.getPriority() && intersection!=bddEngine.BDDFalse){
                int not_rapo_hit = bddEngine.not(r_apo.getHit());
                rule.setHit(bddEngine.and(rule.getHit(),not_rapo_hit));
                bddEngine.deRef(not_rapo_hit);
            }
            bddEngine.deRef(intersection);
            if(rule.getHit()==bddEngine.BDDFalse){
                break;
            }
        }
        return rule.getHit();
    }

    public void updateInsert(Rule rule){
        BDDEngine bddEngine = this.B.get(rule.getDevice());
        int bddF = bddEngine.encodeIpv4(rule.getMatch(),rule.getPrefix(),rule.getSrc(), rule.getSrcSuffix());
        this.ruleToBddForm.put(rule,bddF);
        int hit = getHit(rule);
        String link = rule.getDevice().getName()+"->"+rule.getOutPort().getDevice().getName();
        if(this.M.containsKey(link)){
            int rapo_hit = this.M.get(link);
            this.M.put(link, bddEngine.or(rapo_hit, hit));
        }else{
            this.M.put(link, hit);
            this.linkToDevice.put(link, rule.getDevice());
        }
        for(Rule rapo: this.deviceToRules.get(rule.getDevice()).getAllOverlappingWith(rule, 32)){
            int tem=bddEngine.and(rapo.getHit(), rule.getHit());
            if(rapo.getPriority()<=rule.getPriority()&&tem!=bddEngine.BDDFalse){
                if(rapo.getOutPort()!=rule.getOutPort()){
                    String link_apo = rule.getDevice().getName()+"->"+rapo.getOutPort().getDevice().getName();
                    this.M.put(link_apo, bddEngine.and(this.M.get(link_apo), bddEngine.not(bddEngine.and(rapo.getHit(),rule.getHit()))));
                    rapo.setHit(bddEngine.and(rapo.getHit(), bddEngine.not(rule.getHit())));
                }
            }
            bddEngine.deRef(tem);
        }
        this.deviceToRules.get(rule.getDevice()).insert(rule, 32);
    }

    public void updateDelete(Rule rule){
        BDDEngine bddEngine = this.B.get(rule.getDevice());
        String link = rule.getDevice().getName()+"->"+rule.getOutPort().getDevice().getName();
        this.M.put(link, bddEngine.and(this.M.get(link),bddEngine.not(rule.getHit())));
        this.deviceToRules.get(rule.getDevice()).remove(rule,32);
        for(Rule rapo: this.deviceToRules.get(rule.getDevice()).getAllOverlappingWith(rule,32)){
            int rapo_match = this.ruleToBddForm.get(rapo);
            int tem=bddEngine.and(rapo_match, rule.getHit());
            if(rapo.getPriority()<=rule.getPriority()&&tem!=bddEngine.BDDFalse){
                if(rapo.getOutPort()!=rule.getOutPort()){
                    String link_apo = rule.getDevice().getName()+"->"+rapo.getOutPort().getDevice().getName();
                    this.M.put(link_apo, bddEngine.or(this.M.get(link_apo), bddEngine.and(rapo_match,rule.getHit())));
                }
                rule.setHit(bddEngine.and(rule.getHit(), bddEngine.not(rapo.getHit())));
                rapo.setHit(bddEngine.or(rapo.getHit(),bddEngine.and(rule.getHit(),bddEngine.not(rapo.getHit()))));
                if(rule.getHit()==bddEngine.BDDFalse){
                    break;
                }
            }
            bddEngine.deRef(tem);
        }
        this.ruleToBddForm.remove(rule);
    }

    @Override
    public void run(){
       /* Runtime.getRuntime().gc();
        double memoryBefore = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        this.t1=-System.nanoTime();*/
        for(Pair<Boolean, Rule> rulePair:region.getUpdateSequence()){
            if(rulePair.getFirst()){
                this.updateInsert(rulePair.getSecond());
            }else{
                this.updateDelete(rulePair.getSecond());
            }
        }
        /*this.t1+=System.nanoTime();
        this.t1/=this.region.getSequenceSize();
        this.t2=-System.nanoTime();*/
        for(String link:this.M.keySet()){
            BDDEngine bddEngine = this.B.get(this.linkToDevice.get(link));
            deltaMap.put(link,bddEngine.getBdd().getSet(this.M.get(link)));
        }
        /*this.t2+=System.nanoTime();
        this.t2/=this.region.getSequenceSize();
        double memoryAfter = Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
        double byte2MB = 1024L * 1024L;
        double ret = ((memoryAfter - memoryBefore) / byte2MB);
        this.m=ret;*/
    }

    public double getM(){
        return this.m;
    }

    public double getT1(){
        return this.t1;
    }

    public double getT2(){
        return this.t2;
    }
}
public class Partitioner {
    public Partitioner(Network network) {
        System.out.println("Process start");
        System.out.println(network.updateSequence.size());
        double byte2MB = 1024L * 1024L;
        Runtime.getRuntime().gc();
        double memoryBefore = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
        double totalS = -System.nanoTime();
        /*double s = -System.nanoTime();*/
        Map<Device,Integer> countMap = new HashMap<>();
        Map<Device,Region> device2Region = new HashMap<>();
        for(Pair<Boolean, Rule> pair:network.updateSequence){
            Device nowDevice = pair.getSecond().getDevice();
            countMap.put(nowDevice,countMap.getOrDefault(nowDevice,0)+1);
        }
        Queue<Pair<Device,Integer>> deviceQ = new PriorityQueue<>(new DeviceComparator());
        for(Device it:countMap.keySet()) deviceQ.add(new Pair<>(it,countMap.get(it)));
        Queue<Region> regionQ = new PriorityQueue<>(new RegionComparator());
        for(int i=1;i<=8;i++){
            regionQ.add(new Region());
        }
        while(!deviceQ.isEmpty()){
            Pair<Device,Integer> p=deviceQ.poll();
            Region popRegion = regionQ.poll();
            popRegion.insertDevice(p.getSecond());
            regionQ.add(popRegion);
            device2Region.put(p.getFirst(),popRegion);
        }
        for(Pair<Boolean, Rule> pair:network.updateSequence){
            Device nowDevice = pair.getSecond().getDevice();
            Region nowRegion = device2Region.get(nowDevice);
            nowRegion.insertUpdate(pair);
        }
        Map<String, List<String>> deltaMap=new HashMap<>();
        List<EPModel> epModels=new ArrayList<>();
        /*s+= System.nanoTime();
        System.out.println("Partion time cost "+(s/1000/network.updateSequence.size())+"us per update");
        Runtime.getRuntime().gc();
        double memoryAfter = Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
        double ret = ((memoryAfter - memoryBefore) / byte2MB);
        System.out.println("Partion memory cost "+(ret)+"MB");*/
        while (!regionQ.isEmpty()){
            EPModel epModel=new EPModel(regionQ.poll(),deltaMap);
            epModels.add(epModel);
            epModel.setPriority(10);
            epModel.start();
        }
        try {
            for(EPModel epModel:epModels) epModel.join();
        }catch (Exception e){
            System.out.println(e);
        }
        /*double t1=0;
        double t2=0;
        double m=0;
        for(EPModel epModel:epModels){
            t1 += epModel.getT1();
            t2 += epModel.getT2();
            m+=epModel.getM();
        }
        t1/=epModels.size();
        t2/=epModels.size();
        System.out.println("EP update time cost "+(t1/1000)+"us per update");
        System.out.println("EP merge time cost "+(t2/1000)+"us per update");
        System.out.println("EP  memory cost "+(m)+"MB");*/
        GlobalModel globalModel = new GlobalModel();
        globalModel.transferEP(deltaMap);
        totalS+=System.nanoTime();
        Runtime.getRuntime().gc();
        double memoryAfter = Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
        double ret = ((memoryAfter - memoryBefore) / byte2MB);
        /*System.out.println("Global update time cost "+(globalModel.getT()/1000/network.updateSequence.size())+"us per update");
        System.out.println("Global update memory cost "+(globalModel.getM())+"MB");*/
        System.out.println("Total time cost "+(totalS/1000/network.updateSequence.size())+"us per update");
        System.out.println("Total memory cost "+(ret)+"MB");
    }
}
