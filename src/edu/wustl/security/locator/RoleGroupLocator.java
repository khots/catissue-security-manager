package edu.wustl.security.locator;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.wustl.common.security.exceptions.SMException;
import edu.wustl.common.util.global.XMLParserUtility;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.beans.RoleGroupDetailsBean;
import edu.wustl.security.global.ProvisionManager;
import edu.wustl.security.manager.SecurityManager;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.exceptions.CSException;

/**
 * 
 * @author deepti_shelar
 *
 */
public class RoleGroupLocator
{
	/**
	 * logger Logger - Generic logger.
	 */
	protected static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);

	/**
	 * File name for privilege configuration.
	 */
	private static final String ROLE_GROUP_CONF_FILE="SMRoleGroupConf.xml";
	private static final String ELE_ROLE="Role";
	private static Map<RoleGroupDetailsBean, RoleGroupDetailsBean> roleGroupDetailsMap = new HashMap<RoleGroupDetailsBean, RoleGroupDetailsBean>();
	private static List<String> roleIdList = new ArrayList<String>();
	private static List<String> groupIdList = new ArrayList<String>();
	/**
	 * 
	 */
	public static void init()
	{
		Document doc = XMLParserUtility.getDocument(ROLE_GROUP_CONF_FILE);
		NodeList roleList = doc.getElementsByTagName(ELE_ROLE);
		createRoleGroupBeans(roleList);
	}
	/**
	 * 
	 * @param roleList
	 */
	private static void createRoleGroupBeans(NodeList roleList) {
		for (int s = 0; s < roleList.getLength(); s++)
		{
			Node role = roleList.item(s);
			if (role.getNodeType() == Node.ELEMENT_NODE)
			{
				createRoleGroupBean(role);
			}
		}
	}
	/**
	 * 
	 * @param role
	 */
	private static void createRoleGroupBean(Node role) {
		try 
		{
			Element roleElement = (Element) role;
			String roleName = XMLParserUtility.getElementValue(roleElement,"RoleName");
			String roleType = XMLParserUtility.getElementValue(roleElement,"RoleType");
			String groupName = XMLParserUtility.getElementValue(roleElement,"GroupName");
			String groupType = XMLParserUtility.getElementValue(roleElement,"GroupType");

			String roleId = ProvisionManager.getRoleID(roleName);
			String groupId = ProvisionManager.getGroupID(groupName);
			RoleGroupDetailsBean bean = new RoleGroupDetailsBean();
			bean.setGroupType(groupType);
			bean.setRoleName(roleName);
			bean.setRoleType(roleType);
			bean.setGroupName(groupName);
			bean.setGroupId(groupId);
			bean.setRoleId(roleId);
			roleIdList.add(roleId);
			groupIdList.add(groupId);
			roleGroupDetailsMap.put(bean, bean);
		} catch (CSException e) {
			logger.warn("Error in initializing rolegroupNamevsId map",e);
			e.printStackTrace();
		} catch (SMException e) {
			logger.warn("Error in initializing rolegroupNamevsId map",e);
			e.printStackTrace();
		}
	}
	/**
	 * @return the roleGroupDetailsMap
	 */
	public static Map<RoleGroupDetailsBean, RoleGroupDetailsBean> getRoleGroupDetailsMap() {
		return roleGroupDetailsMap;
	}
	/**
	 * @return the roleGroupDetailsMap
	 */
	public static List<String> getAllRoleIds() {
		
		return roleIdList;
	}
	/**
	 * @return the roleGroupDetailsMap
	 */
	public static List<String> getAllGroupIds() {
		
		return roleIdList;
	}
}
