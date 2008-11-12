package edu.wustl.security.locator;

import java.util.HashMap;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.wustl.common.util.global.XMLParserUtility;
import edu.wustl.security.privilege.Privilege;

/**
 * This class loada all privileges from xml file.
 * @author ravi_kumar
 */
public final class PrivilegeLocator
{
	static PrivilegeLocator locator = new PrivilegeLocator();
	private PrivilegeLocator()
	{
		init();
	}
	public static PrivilegeLocator getInstance()
	{
		return locator;
	}
	/**
	 * File name for privilege configuration.
	 */
	private  final String PRIV_CONF_FILE="PrivilegeConf.xml";

	/**
	 * Element name for 'privilege'.
	 */
	private  final String ELE_PRIVILEGE="privilege";

	/**
	 * Element name for 'bit-number'.
	 */
	private  final String ELE_BIT_NUM="bit-number";

	/**
	 * Element name for 'role-name'.
	 */
	private  final String ELE_ROLE_NAME="role-name";

	/**
	 * Attribute name for 'name'.
	 */
	private  final String ATTR_NAME="name";

	/**
	 * Map of privilege Name and Privilege Object.
	 */
	 private Map<String,Privilege> namePrivMap;

	/**
	 * Map of bit-number and Privilege Object.
	 */
	 private Map<Integer,Privilege> bitPrivMap;
	
	/**
	 * This method returns Privilege object by privilege name.
	 * @param name Privilege Name
	 * @return Privilege object.
	 */
	public Privilege getPrivilegeByName(String name)
	{
		return namePrivMap.get(name);
	}

	/**
	 * This method returns Privilege object by bit number.
	 * @param bit bit number associated with privilege.
	 * @return Privilege object.
	 */
	 public Privilege getPrivilegeByBit(Integer bit)
	{
		return bitPrivMap.get(bit);
	}

	/**
	 * This method load the Privileges into map.
	 */
	 public void init()
	{
		Document doc = XMLParserUtility.getDocument(PRIV_CONF_FILE);
		NodeList privNodeLst = doc.getElementsByTagName(ELE_PRIVILEGE);
		populateMaps(privNodeLst);
	}

	/**
	 * @param privNodeLst this method populate xml data to maps.
	 */
	 private void populateMaps(NodeList privNodeLst)
	{
		Node privNode;
		namePrivMap= new HashMap<String, Privilege>();
		bitPrivMap= new HashMap<Integer, Privilege>();
		for (int s = 0; s < privNodeLst.getLength(); s++)
		{
		    privNode = privNodeLst.item(s);
		    if (privNode.getNodeType() == Node.ELEMENT_NODE)
		    {
		    	addNewPrivilegeToMap(privNode);
		    }
		}
	}

	/**
	 * @param privNode Node- xml privilege node
	 */
	 private void addNewPrivilegeToMap(Node privNode)
	{
	    String privName;
		int bitNumber;
		String roleName;
		Privilege privilege;
		Element privElmnt = (Element) privNode;
	    privName=privElmnt.getAttribute(ATTR_NAME);
	    bitNumber = Integer.parseInt(XMLParserUtility.getElementValue(privElmnt,ELE_BIT_NUM));
	    roleName = XMLParserUtility.getElementValue(privElmnt,ELE_ROLE_NAME);
	    privilege= new Privilege(privName,bitNumber,roleName);
	    namePrivMap.put(privName, privilege);
	    bitPrivMap.put(bitNumber,privilege);
	}
}