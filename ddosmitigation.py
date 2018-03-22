import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import subprocess, os
from ryu.base import app_manager

class BandwidthMonitor(simple_switch_13.SimpleSwitch13):
    
  
    QUERY_DURATION = 5 # after every QUERY_DURATION flow stats data is requested
    
    LIMIT_ATTACKER_COUNT = 2 # number of times ingress filter is applied before packets are dropped

    BANDWIDTH_THRESHOLD = 1000 # if bandwidth is greater than BANDWIDTH_THRESHOLD, its a DDosattack
    
    COUNT_REMOVE_BLOCK = 0 # flag to check the applied drop policy 
   
    NO_ATTACK_THRESHOLD = 50 # if bandwidth is lesser than NO_ATTACK_THRESHOLD, attacker has stopped the flooding and hence remove ingress policy
    
	
    def __init__(self, *args, **kwargs): #constructor
        
        super(BandwidthMonitor, self).__init__(*args, **kwargs)

        self.DDoSattackers = set() #set of attackers in the topology

        self.noAttackCount =  {"s1":  [0,0,0],       #dictionary to map and store switchtoport noAttackCount 
                               "s11": [0,0,0],
                               "s12": [0,0,0]}
       
        self.DropPolicyApplied = {"s1": [False, False, False],     #dictionary to map and set switchtoport DropPolicyApplied, indexes take the boolean values
                               "s11": [False, False, False],
                               "s12": [False, False, False]}
       
        self.IngressPolicyApplied = {"s1": [False, False, False],    #dictionary to map and set switchtoport IngressPolicyApplied, indexes take the boolean values
                               "s11": [False, False, False],
                               "s12": [False, False, False]}


        self.linkbandwidth = {"s1": [{}, {}, {}],          #a dictionary to map and set switchtoport which in turn is mapped to the eth_dest and current rate is set.
                              "s11": [{}, {}, {}], 
                              "s12": [{}, {}, {}]}
        
        self.TopologyPortMapping = {"s1": ["s11", "s12"],
                        	"s11": ["h1", "h2", "s1"],
                        	"s12": ["h3", "h4", "s1"]}

        self.dpids = {0x1: "s1", 
                 0xb: "s11",
                 0xc: "s12"}

	self.hostNametoMacId = {'0a:0a:00:00:00:01' :'h1',
				'0a:0a:00:00:00:02' :'h2',
				'0a:0b:00:00:00:01' :'h3',
				'0a:0b:00:00:00:02' :'h4'
				}
        self.NoOfIngressApplied =  {"h1":  [0],
                               "h2": [0],
                               "h3": [0],
				"h4":[0]}
 
        self.datapaths = {}

        self.FlowStateByteCount = {}
        self.ATTACK_COUNT = 0
     
        self.monitor_thread = hub.spawn(self._monitor)
       

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_flow_stats(dp)
            hub.sleep(self.QUERY_DURATION)

    def _request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        
        DDosVictims = set()

        body = ev.msg.body

        dpid = int(ev.msg.datapath.id)
        switch = self.dpids[dpid]

        print "-------------- Flow stats for switch", switch, "---------------"
        
	print "in-port       eth-dst       out-port    bitrate"
        print "-------- ----------------- --------    --------"
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key =lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):

            inPort = stat.match['in_port']
            outPort = stat.instructions[0].actions[0].port
            ethDst = stat.match['eth_dst']

            key = (dpid, inPort, ethDst, outPort)
            current_rate = 0
            if key in self.FlowStateByteCount:
                cnt = self.FlowStateByteCount[key]
                current_rate = self.bitrate(stat.byte_count - cnt)

            self.FlowStateByteCount[key] = stat.byte_count
               
            print " %x       %s%8x     %f" % (inPort, ethDst, outPort, current_rate)
            

            self.linkbandwidth[switch][inPort - 1][str(ethDst)] = current_rate

            if current_rate > BandwidthMonitor.BANDWIDTH_THRESHOLD:
                victim = str(ethDst)
                self.noAttackCount[switch][inPort-1] = 0
                DDosVictims.add(victim)
            
	for port in range(len(self.IngressPolicyApplied[switch])):
            if not self.IngressPolicyApplied[switch][port]:
                continue 
            if all(rate <= BandwidthMonitor.NO_ATTACK_THRESHOLD for rate in self.linkbandwidth[switch][port].values()):
                self.noAttackCount[switch][port] += 1
            else:
                self.noAttackCount[switch][port] = 0   
        
                
        self.handleAttackers(DDosVictims)
        
	
	self.checkForIngressPolicyRemoval()
       
        print "--------------------------------------------------------"
        
    def handleAttackers(self, DDosVictims):
 
        DDoSattackers = set()
        for victim in DDosVictims:
            victim_Host, victim_Switch, victim_Port = self.getHostVictim(victim)
            print("Identified victimMAC %s \n victimHost %s \n victimSwitch %s \n victimPort %s\n" % (victim, victim_Host, victim_Switch, victim_Port))
            victim_Attackers = self.getAttackers(victim)
            print("Attackers  %s: - victim %s" % (victim_Attackers, victim_Host))
            if victim_Attackers:
               DDoSattackers = DDoSattackers.union(victim_Attackers)
        
        if DDoSattackers:
	    self.ATTACK_COUNT += 1
	    #print "No of attacks attempts:" + str(self.ATTACK_COUNT/3)
	    for attacker in DDoSattackers:
		print "NoOfIngressApplied:" + str((self.NoOfIngressApplied[attacker][0])/3)
            	if self.NoOfIngressApplied[attacker][0]/3 < self.LIMIT_ATTACKER_COUNT:
			self.NoOfIngressApplied[attacker][0] +=1
                	self.applyIngress(attacker)
	    	else:
			self.NoOfIngressApplied[attacker][0] = 0
			print "apply drop policy"
			
			while(1):
				self.applyDropPolicy(attacker, victim)
				if self.COUNT_REMOVE_BLOCK > 5:
					print "------------waited for 5 iteration-------------"
					break
			
			self.checkForDropPolicyRemoval(victim)

	else:
	    self.ATTACK_COUNT = 0
		

    def applyDropPolicy(self, attacker, victim, DropApplyFlag = True):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
        if self.DropPolicyApplied[attackerSwitch][int(attackerPort) - 1] == DropApplyFlag:
	    self.COUNT_REMOVE_BLOCK += 1
            return

        if DropApplyFlag:
		subprocess.check_output(["sudo", "ovs-ofctl", "add-flow", attackerSwitch, "in_port="+attackerPort+ "," + "dl_dst="+victim +"," +"priority=2,actions=drop"])
		print("-------------Applying Drop policy on %s, on switch %s at port %s--------" % (attacker, attackerSwitch, attackerPort))
                self.DropPolicyApplied[attackerSwitch][int(attackerPort) - 1] = DropApplyFlag
		#self.noAttackCount[attackerSwitch][int(attackerPort)-1] = 0

        
    def checkForDropPolicyRemoval(self, eth_dst):
        for switch in self.DropPolicyApplied:
            for port in range(len(self.DropPolicyApplied[switch])):
		#print self.noAttackCount[switch][int(port)]
                if  self.DropPolicyApplied[switch][port]:
   			string = "sudo ovs-ofctl del-flows " + str(switch)  + " in_port="+ str(port+1)+",dl_dst="+str(eth_dst)
			print("-------------removed Drop Policy on switch %s at port %s for destMAC %s--------" % (switch, str(port+1), str(eth_dst)))
			#print "remove drop policy:" + string
                        os.system(string)
			self.DropPolicyApplied[switch][int(port)] = False



    def checkForIngressPolicyRemoval(self):
        for switch in self.IngressPolicyApplied:
            for port in range(len(self.IngressPolicyApplied[switch])):
                if self.noAttackCount[switch][int(port)] > self.ATTACK_COUNT/3 and self.IngressPolicyApplied[switch][port]:
			self.applyIngress(self.TopologyPortMapping[switch][int(port)], False)

 
    def applyIngress(self, attacker, applyIngress= True):
        attackerSwitch, attackerPort = self.getSwitch(attacker)
        if self.IngressPolicyApplied[attackerSwitch][int(attackerPort) - 1] == applyIngress:
           return

        ingressPolicingBurst, ingressPolicingRate = "ingress_policing_burst=0", "ingress_policing_rate=0"
        ApplyBurstPolicy = "ingress_policing_burst=100"
        ApplyRatePolicy =  "ingress_policing_rate=50"

        if applyIngress:
		print("-------------Applying ingress filters on %s, on switch %s at port %s--------" % (attacker, attackerSwitch, attackerPort))
        	subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ApplyBurstPolicy])
        	subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ApplyRatePolicy])
		self.IngressPolicyApplied[attackerSwitch][int(attackerPort) - 1] = True
        else:
		print ("-------------removed ingress filters on %s, on switch %s at port %s--------" % (attacker, attackerSwitch, attackerPort))
		ApplyBurstPolicy = "ingress_policing_burst=0"
                ApplyRatePolicy =  "ingress_policing_rate=0"
		subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ApplyBurstPolicy])
        	subprocess.call(["sudo", "ovs-vsctl", "set", "interface", attackerSwitch + "-eth" + attackerPort, ApplyRatePolicy])
		self.IngressPolicyApplied[attackerSwitch][int(attackerPort) - 1] = False


    def getHostVictim(self, victim):
        victim_Host = self.hostNametoMacId[victim]
        for sw in self.TopologyPortMapping:
            for index in range(len(self.TopologyPortMapping[sw])):
                if self.TopologyPortMapping[sw][index] == victim_Host:
		    port = str(index + 1)
                    return victim_Host, sw, port

    def getAttackers(self, victim):
        DDoSattackers = set()
        for switch in self.linkbandwidth:
            for port in range(len(self.linkbandwidth[switch])):
                if victim not in self.linkbandwidth[switch][port]:
                    continue

                if self.linkbandwidth[switch][port][victim] > BandwidthMonitor.BANDWIDTH_THRESHOLD:
                    attacker = self.TopologyPortMapping[switch][port]
                    if attacker[0] != 's':
                        DDoSattackers.add(attacker)
                    
        return DDoSattackers


    def getSwitch(self, node):
        for sw in self.TopologyPortMapping:
            if node in self.TopologyPortMapping[sw]:
                return sw, str(self.TopologyPortMapping[sw].index(node) + 1)

    @staticmethod
    def bitrate(bytes):
        return bytes * 8.0 / (BandwidthMonitor.QUERY_DURATION * 1000)
