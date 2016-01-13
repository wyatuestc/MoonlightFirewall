package org.moonlightcontroller.samples;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import org.moonlightcontroller.bal.BoxApplication;
import org.moonlightcontroller.blocks.Alert;
import org.moonlightcontroller.blocks.Discard;
import org.moonlightcontroller.blocks.FromDevice;
import org.moonlightcontroller.blocks.FromDump;
import org.moonlightcontroller.blocks.HeaderClassifier;
import org.moonlightcontroller.blocks.HeaderClassifier.HeaderClassifierRule;
import org.moonlightcontroller.blocks.Log;
import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.events.IAlertListener;
// import org.moonlightcontroller.blocks.ToDevice;
import org.moonlightcontroller.events.IHandleClient;
import org.moonlightcontroller.events.IInstanceUpListener;
import org.moonlightcontroller.events.InstanceAlertArgs;
import org.moonlightcontroller.events.InstanceUpArgs;
import org.moonlightcontroller.managers.models.messages.AlertMessage;
import org.moonlightcontroller.processing.Connector;
import org.moonlightcontroller.processing.IConnector;
import org.moonlightcontroller.processing.IProcessingBlock;
import org.moonlightcontroller.processing.ProcessingGraph;
import org.moonlightcontroller.samples.actions.Action;
import org.moonlightcontroller.samples.actions.ActionAlert;
import org.moonlightcontroller.samples.actions.ActionDrop;
import org.moonlightcontroller.samples.actions.ActionLog;
import org.moonlightcontroller.samples.actions.ActionOutput;
import org.openboxprotocol.protocol.IStatement;
import org.openboxprotocol.protocol.Priority;
import org.openboxprotocol.protocol.Statement;
import org.openboxprotocol.protocol.topology.IApplicationTopology;
import org.openboxprotocol.protocol.topology.TopologyManager;

import com.google.common.collect.ImmutableList;

public class Firewall extends BoxApplication{

	private final static Logger LOG = Logger.getLogger(Firewall.class.getName());
	
	public static final String PROPERTIES_PATH = "Firewall.properties";

	public static final String PROP_SEGMENT = "segment";
	public static final String PROP_IN_IFC = "in_ifc";
	public static final String PROP_IN_DUMP = "in_dump";
	public static final String PROP_IN_USE_IFC = "in_use_ifc";
	public static final String PROP_RULE_FILE = "rule_file";
	
	public static final String DEFAULT_SEGMENT = "220";
	public static final String DEFAULT_IN_IFC = "eth0";
	public static final String DEFAULT_IN_DUMP = "in_dump.pcap";
	public static final String DEFAULT_IN_USE_IFC = "true";
	public static final String DEFAULT_RULE_FILE = "firewall_rules.txt";
	
	private static final Properties DEFAULT_PROPS = new Properties();
	
	static {
		DEFAULT_PROPS.setProperty(PROP_SEGMENT, DEFAULT_SEGMENT);
		DEFAULT_PROPS.setProperty(PROP_IN_IFC, DEFAULT_IN_IFC);
		DEFAULT_PROPS.setProperty(PROP_IN_DUMP, DEFAULT_IN_DUMP);
		DEFAULT_PROPS.setProperty(PROP_IN_USE_IFC, DEFAULT_IN_USE_IFC);
		DEFAULT_PROPS.setProperty(PROP_RULE_FILE, DEFAULT_RULE_FILE);
	}
	
	private Properties props;
	
	public Firewall() {
		super("Firewall");
		
		props = new Properties(DEFAULT_PROPS);
		File f = new File(PROPERTIES_PATH);
		try {
			props.load(new FileReader(f));
		} catch (IOException e) {
			LOG.severe("Cannot load properties file from path: " + f.getAbsolutePath());
			LOG.severe("Using default properties.");
		}
		LOG.info(String.format("Firewall is running on Segment %s", props.getProperty(PROP_SEGMENT)));
		LOG.info(String.format("[->] Input: %s", (Boolean.parseBoolean(props.getProperty(PROP_IN_USE_IFC)) ? props.getProperty(PROP_IN_IFC) : props.getProperty(PROP_IN_DUMP))));
		LOG.info(String.format("[>|] Rule files path: %s", props.getProperty(PROP_RULE_FILE)));
		
		this.setStatements(createStatements());
		this.setInstanceUpListener(new InstanceUpHandler());
		this.setAlertListener(new IAlertListener() {
			
			@Override
			public void Handle(InstanceAlertArgs args) {
				for (AlertMessage a : args.getAlert().getMessages()) {
					LOG.info(a.toString());
				}
			}
		});
	}
	
	@Override
	public void handleAppStart(IApplicationTopology top, IHandleClient handles) {
		LOG.info("Got App Start Event");
	}
	
	private List<IStatement> createStatements() {
		// Compile rules file to a graph
		
		List<IProcessingBlock> blocks = new ArrayList<>();
		List<IConnector> connectors = new ArrayList<>();
		List<HeaderClassifierRule> headerRules = new ArrayList<>();
		List<Rule> rules;
		
		try {
			rules = new RuleParser(props.getProperty(PROP_RULE_FILE)).read();
		} catch (Exception e) {
			LOG.severe("Failed to parse rule file");
			return ImmutableList.of();
		}

		HeaderClassifier classify = new HeaderClassifier("HeaderClassifier_Snort", headerRules, Priority.HIGH);
		blocks.add(classify);
		
		int i = 0;
		for (Rule r : rules) {
			headerRules.add(new HeaderClassifierRule.Builder()
				.setHeaderMatch(r.getHeaderMatch())
				.setPriority(r.getPriority())
				.setOrder(i)
				.build());
			
			IProcessingBlock last = classify;
			int lastOutPort = i;
			int j = 0;
			boolean stop = false;
			for (Action action : r.getActions()) {
				IProcessingBlock block;
				String suffix = String.format("_Firewall_Rule_%d_UID_%d", i, j);
				if (action instanceof ActionAlert) {
					block = new Alert("Alert" + suffix, ((ActionAlert)action).getMessage());
				} else if (action instanceof ActionOutput) {
					block = new ToDevice("ToDevice" + suffix, ((ActionOutput)action).getInterface());
				} else if (action instanceof ActionDrop) {
					block = new Discard("Discard" + suffix);
					stop = true;
				} else if (action instanceof ActionLog) {
					block = new Log("Log" + suffix, ((ActionLog)action).getMessage());
				} else {
					LOG.severe("Unknown action: " + action.getType());
					continue;
				}
				blocks.add(block);
				connectors.add(new Connector.Builder().setSourceBlock(last).setSourceOutputPort(lastOutPort).setDestBlock(block).build());
				last = block;
				lastOutPort = 0;
				j++;
				if (stop)
					break;
			}
			
			i++;
		}
		
		FromDevice fromDevice = new FromDevice("FromDevice_Snort", props.getProperty(PROP_IN_IFC), true, true);
		FromDump fromDump = new FromDump("FromDump_Snort", props.getProperty(PROP_IN_DUMP), false, true);

		IProcessingBlock from = (Boolean.parseBoolean(props.getProperty(PROP_IN_USE_IFC))) ?
				fromDevice : fromDump;
		
		blocks.add(from);
		connectors.add(
			new Connector.Builder().setSourceBlock(from).setSourceOutputPort(0).setDestBlock(classify).build()
		);
		
		int segment;
		try {
			segment = Integer.parseInt(props.getProperty(PROP_SEGMENT));
		} catch (NumberFormatException e) {
			segment = Integer.parseInt(DEFAULT_SEGMENT);
			LOG.info("Error parsing segment property. Using default segment: " + segment);
		}
		
		IStatement st = new Statement.Builder()
			.setLocation(TopologyManager.getInstance().resolve(segment))
			.setProcessingGraph(new ProcessingGraph.Builder().setBlocks(blocks).setConnectors(connectors).setRoot(from).build())
			.build();
		
		return Collections.singletonList(st);
	}
	
	private class InstanceUpHandler implements IInstanceUpListener {

		@Override
		public void Handle(InstanceUpArgs args) {
			LOG.info("Instance up for Snort: " + args.getInstance().toString());	
		}
	}

}