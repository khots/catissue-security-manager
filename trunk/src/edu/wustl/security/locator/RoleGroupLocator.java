
package edu.wustl.security.locator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.wustl.common.util.global.XMLParserUtility;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.beans.RoleGroupDetailsBean;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.global.ProvisionManager;
import edu.wustl.security.global.Utility;
import edu.wustl.security.manager.SecurityManager;
import gov.nih.nci.security.exceptions.CSException;

/**
 * Reads SMRoleGroupConf.xml anad loads a map of bean objects having details of Role and group.
 * @author deepti_shelar
 *
 */
public final class RoleGroupLocator
{

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);

	/**
	 * File name for privilege configuration.
	 */
	private static final String CONF_FILE = "SMRoleGroupConf.xml";
	/**
	 * ELE_ROLE.
	 */
	private static final String ELE_ROLE = "Role";
	/**
	 * 
	 */
	private Map<RoleGroupDetailsBean, RoleGroupDetailsBean> roleGrpMap = 
		new HashMap<RoleGroupDetailsBean, RoleGroupDetailsBean>();
	/**
	 * 
	 */
	private List<String> roleIdList = new ArrayList<String>();
	/**
	 * 
	 */
	private List<String> groupIdList = new ArrayList<String>();
	/**
	 * Instantiating the class whenever loaded for the first time.
	 *  The same instance will be returned whenever getInstance is called. 
	 */
	private static RoleGroupLocator locator = new RoleGroupLocator();
	/**
	 * 
	 */
	private static boolean isSuccess = true;
	/**
	 * Making the class singleton.
	 */
	private RoleGroupLocator()
	{
		Document doc = XMLParserUtility.getDocument(CONF_FILE);
		NodeList roleList = doc.getElementsByTagName(ELE_ROLE);
		try
		{
			createRoleGroupBeans(roleList);
		}
		catch (SMException e)
		{
			isSuccess = false;
			logger.error(e.getMessage());
		}
	}

	/**
	 * Singleton class, will return the single object every time.
	 * @return RoleGroupLocator instance
	 * @throws SMException 
	 */
	public static RoleGroupLocator getInstance() throws SMException
	{
		if(!isSuccess)
		{
			String mess = "error occured in instantiation of PrivilegeManager";
			Utility.getInstance().throwSMException(null,mess);
		}
		return locator;
	}

	/**
	 * Creates bean objects for role and group details mentioned in RoleGroupConf xml.
	 * @param roleList list
	 * @throws SMException 
	 */
	private void createRoleGroupBeans(NodeList roleList) throws SMException
	{
		for (int s = 0; s < roleList.getLength(); s++)
		{
			Node role = roleList.item(s);
			if (role.getNodeType() == Node.ELEMENT_NODE)
			{
				try
				{
					createRoleGroupBean(role);
				}
				catch (SMException e)
				{
					String mess = "error in creating role grp bean"+e.getMessage();
				//	logger.error(mess);
					Utility.getInstance().throwSMException(e, mess);
				}
			}
		}
	}

	/**
	 * Creates a bean object for role and group details.
	 * @param role role
	 * @throws SMException exc 
	 */
	private void createRoleGroupBean(Node role) throws SMException
	{
		try
		{
			Element roleElement = (Element) role;
			String roleName = XMLParserUtility.getElementValue(roleElement, "RoleName");
			String roleType = XMLParserUtility.getElementValue(roleElement, "RoleType");
			String groupName = XMLParserUtility.getElementValue(roleElement, "GroupName");
			String groupType = XMLParserUtility.getElementValue(roleElement, "GroupType");

			String roleId = ProvisionManager.getInstance().getRoleID(roleName);
			String groupId = ProvisionManager.getInstance().getGroupID(groupName);
			RoleGroupDetailsBean bean = new RoleGroupDetailsBean();
			bean.setGroupType(groupType);
			bean.setRoleName(roleName);
			bean.setRoleType(roleType);
			bean.setGroupName(groupName);
			bean.setGroupId(groupId);
			bean.setRoleId(roleId);
			roleIdList.add(roleId);
			groupIdList.add(groupId);
			roleGrpMap.put(bean, bean);
		}
		catch (CSException e)
		{
			String mess = "Error in initializing rolegroupNamevsId map";
			Utility.getInstance().throwSMException(e, mess);
		}
		catch (SMException e)
		{
			String mess = "Error in initializing rolegroupNamevsId map";
			Utility.getInstance().throwSMException(e, mess);
		}
	}

	/**
	 * @return the roleGrpMap
	 */
	public Map<RoleGroupDetailsBean, RoleGroupDetailsBean> getRoleGroupDetailsMap()
	{
		return roleGrpMap;
	}

	/**
	 * @return the roleGrpMap
	 */
	public List<String> getAllRoleIds()
	{

		return roleIdList;
	}

	/**
	 * @return the roleGrpMap
	 */
	public List<String> getAllGroupIds()
	{

		return groupIdList;
	}
}
