/**
 * PrivilegeCache will cache all privileges for a specific user. 
 * An instance of PrivilegeCache will be created for every user who logs in.
 */

package edu.wustl.common.security;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import edu.wustl.common.beans.NameValueBean;
import edu.wustl.common.domain.AbstractDomainObject;
import edu.wustl.common.security.exceptions.SMException;
import edu.wustl.common.util.Permissions;
import edu.wustl.common.util.Utility;
import edu.wustl.common.util.global.CSMGroupLocator;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.global.Constants;
import gov.nih.nci.security.authorization.ObjectPrivilegeMap;
import gov.nih.nci.security.authorization.domainobjects.Privilege;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.ProtectionGroup;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.dao.ProtectionElementSearchCriteria;
import gov.nih.nci.security.exceptions.CSException;
/**
 * @author ravindra_jain creation date : 14th April, 2008
 * @version 1.0
 */
public class PrivilegeCache
{

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(PrivilegeCache.class);
	/*
	 * login name of the user who has logged in
	 */
	private String loginName;

	/*
	 * the map of object id and corresponding permissions / privileges
	 */
	private Map<String, BitSet> privilegeMap;

	/**
	 * After initialization of the variables, a call to method 'initialize()'
	 * is made initialize() uses some ProtectionElementSearchCriterias & gets
	 * Protection Elements from the database
	 * 
	 * @throws Exception
	 */
	public PrivilegeCache(String loginName) throws Exception
	{
		privilegeMap = new HashMap<String, BitSet>();
		this.loginName = loginName;

		initialize();
	}

	/**
	 * This method gets Protection Elements we are interested in, from the
	 * database We achieve this by using the ProtectionElementSearchCriteria
	 * provided by CSM Then, a call to getPrivilegeMap is made & we get a
	 * Collection of ObjectPrivilegeMap for each call Here, for every passed
	 * ProtectionElement,the method looks for the privileges that User has on
	 * the ProtectionElement such ObjectPrivilegeMaps are then passed to
	 * 'populatePrivileges' method.
	 * 
	 * @throws Exception
	 */
	private void initialize() throws Exception
	{
		for (String className : PrivilegeManager.getInstance().getClasses())
		{
			Collection objPrivMap = getObjectPrivilegeMap(className);
			populatePrivileges(objPrivMap);
		}

		for (String objectPattern : PrivilegeManager.getInstance().getEagerObjects())
		{
			Collection objPrivMap = getObjectPrivilegeMap(objectPattern);
			populatePrivileges(objPrivMap);
		}

	}

	private Collection getObjectPrivilegeMap(String protEleObjId)
	{
		Collection objPrivMap = new ArrayList();

		try
		{
			PrivilegeUtility privilegeUtility = new PrivilegeUtility();
			ProtectionElement protectionElement = new ProtectionElement();
			protectionElement.setObjectId(protEleObjId);
			ProtectionElementSearchCriteria protEleSearchCrit = new ProtectionElementSearchCriteria(
					protectionElement);
			List list = privilegeUtility.getUserProvisioningManager().getObjects(
					protEleSearchCrit);

			if (!list.isEmpty())
			{
				objPrivMap = privilegeUtility.getUserProvisioningManager().getPrivilegeMap(
						loginName, list);
			}
		}
		catch (CSException excp)
		{
			logger.error(excp.getMessage(), excp);
		}

		return objPrivMap;
	}

	/**
	 * populatePrivileges does the Mapping (inserts into Map) of the Object Id's
	 * and corresponding BitSets.
	 * 
	 * BitSet is used for the Mapping. There are total 10 possible Privileges /
	 * Permissions. So, we use 10 bits of bitset for storing these Permissions
	 * For every objectId in PrivilegeMap, a bit '1' in BitSet indicates user
	 * has permission on that Privilege & a bit '0' indicates otherwise So, in
	 * this method, we examine each Privilege returned by PrivilegeMap & set the
	 * BitSet corresponding to the objectId accordingly.
	 * 
	 * @param objPrivMapCol
	 */
	private void populatePrivileges(Collection<ObjectPrivilegeMap> objPrivMapCol)
	{
		// To populate the permissionMap
		for (ObjectPrivilegeMap objectPrivilegeMap : objPrivMapCol)
		{
			String objectId = objectPrivilegeMap.getProtectionElement().getObjectId();

			BitSet bitSet = new BitSet();

			for (Object privilege : objectPrivilegeMap.getPrivileges())
			{
				bitSet.set(getBitNumber(((Privilege) privilege).getName()));
			}
			privilegeMap.put(objectId, bitSet);
		}
	}

	/**
	 * Simply checks if the user has any privilage on given object id.
	 *  
	 * @param objectId
	 * @return
	 */
	public boolean hasPrivilege(String objectId)
	{
		boolean hasPrivilege=false;
		BitSet bitSet = privilegeMap.get(objectId);
		if (bitSet != null && bitSet.cardinality() > 0)
		{
			hasPrivilege=true;
		}

		return hasPrivilege;
	}

	/**
	 * To check for 'Class' & 'Action' level Privilege Here, we take className
	 * as the objectId & retrieve its associated BitSet from the privilegeMap
	 * Then, we check whether User has Permission over the passed Privilege or
	 * no & return true if user has privilege, false otherwise.
	 *
	 * @param classObj
	 * @param privilegeName
	 * @return
	 */
	public boolean hasPrivilege(Class classObj, String privilegeName)
	{
		return hasPrivilege(classObj.getName(), privilegeName);
	}

	/**
	 * To check for 'Object' level Privilege Here, we take objectId from Object &
	 * retrieve its associated BitSet from the privilegeMap Then, we check
	 * whether User has Permission over the passed Privilege or no & return true
	 * if user has privilege, false otherwise.
	 *
	 * @param aDObject
	 * @param privilegeName
	 * @return
	 */
	public boolean hasPrivilege(AbstractDomainObject aDObject, String privilegeName)
	{
		return hasPrivilege(aDObject.getObjectId(), privilegeName);
	}

	/**
	 * To check for Privilege given the ObjectId Here, we take objectId &
	 * retrieve its associated BitSet from the privilegeMap Then, we check
	 * whether User has Permission over the passed Privilege or no & return true
	 * if user has privilege, false otherwise.
	 * 
	 * @param objectId
	 * @param privilegeName
	 * @return
	 */
	public boolean hasPrivilege(String objectId, String privilegeName)
	{
		boolean isAuthorized = false;
		BitSet bitSet = privilegeMap.get(objectId);
		if (bitSet == null)
		{
			for (String objectIdPart : PrivilegeManager.getInstance().getLazyObjects())
			{
				if (objectId.startsWith(objectIdPart))
				{
					bitSet = getPrivilegesFromDatabase(objectId);

					break;
				}
			}
		}

		if (bitSet != null)
		{
			isAuthorized = bitSet.get(getBitNumber(privilegeName));
		}
		return isAuthorized;
	}
	/**
	 * 
	 * @param objectId
	 * @return
	 */
	private BitSet getPrivilegesFromDatabase(String objectId)
	{
		PrivilegeUtility privilegeUtility = new PrivilegeUtility();

		BitSet bitSet = privilegeMap.get(objectId);

		try
		{
			ProtectionElement protectionElement = new ProtectionElement();
			protectionElement.setObjectId(objectId);
			ProtectionElementSearchCriteria protEleSearchCrit = new ProtectionElementSearchCriteria(
					protectionElement);
			List list = privilegeUtility.getUserProvisioningManager().getObjects(
					protEleSearchCrit);
			Collection objPrivMap = privilegeUtility.getUserProvisioningManager()
					.getPrivilegeMap(loginName, list);
			populatePrivileges(objPrivMap);
			bitSet = privilegeMap.get(objectId);
		}
		catch (CSException excp)
		{
			logger.error(excp.getMessage(), excp);
		}

		return bitSet;
	}

	public void updatePrivilege(Class classObj, String privilegeName, boolean value)
	{
		updatePrivilege(classObj.getName(), privilegeName, value);
	}

	public void updatePrivilege(AbstractDomainObject aDObject, String privilegeName, boolean value)
	{
		updatePrivilege(aDObject.getObjectId(), privilegeName, value);
	}

	public void updatePrivilege(String objectId, String privilegeName, boolean value)
	{
		BitSet bitSet = privilegeMap.get(objectId);

		if ("READ".equals(privilegeName))
		{
			bitSet.set(getBitNumber("READ_DENIED"), !value);
		}
		else
		{
			bitSet.set(getBitNumber(privilegeName), value);
		}
	}

	/**
	 * This method is used to refresh the Privilege Cache for the user A call to
	 * this method forces CSM to go to the database & get the ProtectionElements
	 * For more, please refer to the 'initialize' method above.
	 *
	 * @throws Exception
	 */
	public void refresh() throws Exception
	{
		initialize();
	}

	private int getBitNumber(String privilegeName)
	{
		return PrivilegeLocator.getPrivilegeByName(privilegeName).getBitNumber();		
	}

	public String getLoginName()
	{
		return loginName;
	}

	public void addObject(String objectId, Collection<Privilege> privileges)
	{
		BitSet bitSet = new BitSet();

		for (Privilege privilege : privileges)
		{
			bitSet.set(getBitNumber(privilege.getName()));
		}
		privilegeMap.put(objectId, bitSet);
	}

	public void updateUserPrivilege(String privilegeName, Class objectType, Long[] objectIds,
			Long userId, boolean assignOperation) throws Exception
	{
		PrivilegeUtility privilegeUtility = new PrivilegeUtility();
		Collection<PrivilegeCache> listOfPrivCaches = null;

		listOfPrivCaches = PrivilegeManager.getInstance().getPrivilegeCaches();

		for (PrivilegeCache privilegeCache : listOfPrivCaches)
		{
			if (privilegeCache.getLoginName().equals(
					privilegeUtility.getUserById(userId.toString()).getLoginName()))
			{
				for (Long objectId : objectIds)
				{
					updatePrivilege(objectType.getName() + "_" + objectId, privilegeName,
							assignOperation);
				}
			}
		}
		assignPrivilegeToUser(privilegeName, objectType, objectIds, userId, assignOperation);
	}

	/**
	 * This method assigns privilege by privilegeName to the user identified by
	 * userId on the objects identified by objectIds.
	 * 
	 * @param privilegeName
	 * @param objectIds
	 * @param userId
	 * @throws SMException
	 * @throws ClassNotFoundException 
	 * @throws ClassNotFoundException 
	 */
	private void assignPrivilegeToUser(String privilegeName, Class objectType, Long[] objectIds,
			Long userId, boolean assignOp) throws SMException, ClassNotFoundException
	{
		boolean assignOperation = assignOp;
		PrivilegeUtility privilegeUtility = new PrivilegeUtility();
		if (privilegeName == null || objectType == null || objectIds == null || userId == null)
		{
			logger.debug("Cannot assign privilege to user. One of the parameters is null.");
		}
		else
		{
			String protGrName = null;
			Role role;
			ProtectionGroup protectionGroup;

			try
			{
				role = privilegeUtility.getRoleByPrivilege(privilegeName);
				Set roles = new HashSet();
				roles.add(role);

				if (privilegeName.equals(Permissions.USE))
				{
					protGrName = "PG_" + userId + "_ROLE_" + role.getId();

					if (assignOperation == Constants.PRIVILEGE_ASSIGN)
					{
						logger.debug("Assign Protection elements");

						protectionGroup = privilegeUtility.getProtectionGroup(protGrName);

						// Assign Protection elements to Protection Group
						privilegeUtility.assignProtectionElements(protectionGroup
								.getProtectionGroupName(), objectType, objectIds);

						privilegeUtility.assignUserRoleToProtectionGroup(userId, roles,
								protectionGroup, assignOperation);
					}
					else
					{
						logger.debug("De Assign Protection elements");
						privilegeUtility.deAssignProtectionElements(protGrName,
								objectType, objectIds);
					}
				}
				else
				{
					assignOperation = !assignOperation;
					CSMGroupLocator locator = new CSMGroupLocator();
					for (int i = 0; i < objectIds.length; i++)
					{
						protGrName = PrivilegeUtility.getProtectionGroupName(objectType,locator);
						protectionGroup = privilegeUtility.getProtectionGroup(protGrName);
						logger.debug("Assign User Role To Protection Group");
						// Assign User Role To Protection Group
						privilegeUtility.assignUserRoleToProtectionGroup(userId, roles,
								protectionGroup, assignOperation);
					}
				}
			}
			catch (CSException csex)
			{
				throw new SMException(csex);
			}
		}
	}

	/**
	 * get the ids and privileges where ids start with the given prefix.
	 * 
	 * @param prefix
	 * @return
	 */
	public Map<String, List<NameValueBean>> getPrivilegesforPrefix(String prefix)
	{
		Map<String, List<NameValueBean>> map = new HashMap<String, List<NameValueBean>>();

		for (Entry<String, BitSet> entry : privilegeMap.entrySet())
		{
			if (entry.getKey().startsWith(prefix))
			{
				List<NameValueBean> privileges = getPrivilegeNames(entry.getValue());
				if (!privileges.isEmpty())
				{
					map.put(entry.getKey(), privileges);
				}
			}
		}

		return map;
	}

	/**
	 * convert the given bitset into a set of privilege names.
	 * 
	 * @param value
	 * @return
	 */
	private List<NameValueBean> getPrivilegeNames(BitSet value)
	{
		List<NameValueBean> privilegeNames = new ArrayList<NameValueBean>();

		for (int i = 0; i < value.size(); i++)
		{
			if (value.get(i))
			{
				NameValueBean nmv = new NameValueBean();
				nmv.setName(PrivilegeLocator.getPrivilegeByBit(i).getPrivilegeName());
				/*switch (i)
				{
					case 17:
						nmv.setName(Permissions.DEFINE_ANNOTATION);
						break;

					case 21 :
						nmv.setName(Permissions.DISTRIBUTION);
						break;

					case 29:
						nmv.setName(Permissions.GENERAL_ADMINISTRATION);
						break;

					
					case 24:
					nmv.setName(Permissions.PARTICIPANT_SCG_ANNOTATION);
					break;
					

					case 16 :
						nmv.setName(Permissions.PROTOCOL_ADMINISTRATION);
						break;

					case 22:
						nmv.setName(Permissions.QUERY);
						break;

					case 18 :
						nmv.setName(Permissions.REGISTRATION);
						break;

					case 14:
						nmv.setName(Permissions.REPOSITORY_ADMINISTRATION);
						break;
						
					case 25:
						nmv.setName(Permissions.SPECIMEN_ANNOTATION);
						break;
					

					case 26 :
						nmv.setName(Permissions.SPECIMEN_PROCESSING);
						break;
						
					case 27:
						nmv.setName(Permissions.SPECIMEN_STORAGE);
						break;
					

					case 15 :
						nmv.setName(Permissions.STORAGE_ADMINISTRATION);
						break;

					case 13 :
						nmv.setName(Permissions.USER_PROVISIONING);
						break;

					case 30 :
						nmv.setName(Permissions.SHIPMENT_PROCESSING);
						break;

					case 1 :
						nmv.setName(Permissions.READ_DENIED);
						break;
				}*/

				for (Object o : Utility.getAllPrivileges())
				{
					NameValueBean privilege = (NameValueBean) o;
					if (privilege.getName().equals(nmv.getName()))
					{
						nmv.setValue(privilege.getValue());
						privilegeNames.add(nmv);
						break;
					}
				}
			}
		}

		return privilegeNames;
	}

}