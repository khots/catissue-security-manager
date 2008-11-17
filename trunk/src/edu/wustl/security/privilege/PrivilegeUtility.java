/**
 * Utility class for methods related to CSM 
 */

package edu.wustl.security.privilege;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import edu.wustl.common.domain.AbstractDomainObject;
import edu.wustl.common.exception.ErrorKey;
import edu.wustl.common.util.Permissions;
import edu.wustl.common.util.global.CSMGroupLocator;
import edu.wustl.common.util.global.Constants;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.beans.SecurityDataBean;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.global.ProvisionManager;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
import edu.wustl.security.manager.ISecurityManager;
import edu.wustl.security.manager.SecurityManagerFactory;
import gov.nih.nci.security.AuthorizationManager;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.domainobjects.Application;
import gov.nih.nci.security.authorization.domainobjects.Group;
import gov.nih.nci.security.authorization.domainobjects.Privilege;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.ProtectionGroup;
import gov.nih.nci.security.authorization.domainobjects.ProtectionGroupRoleContext;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.dao.ApplicationSearchCriteria;
import gov.nih.nci.security.dao.GroupSearchCriteria;
import gov.nih.nci.security.dao.ProtectionGroupSearchCriteria;
import gov.nih.nci.security.dao.RoleSearchCriteria;
import gov.nih.nci.security.dao.SearchCriteria;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.exceptions.CSObjectNotFoundException;
import gov.nih.nci.security.exceptions.CSTransactionException;

/**
 * Utility class for methods related to CSM 
 * 
 * @author ravindra_jain
 *
 */
public class PrivilegeUtility
{

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(PrivilegeUtility.class);
	/**
	 * instance of SecurityManager.
	 */
	private static ISecurityManager securityManager = null;
	/**
	 * 
	 */
	public PrivilegeUtility() 
	{
		try 
		{
			securityManager = SecurityManagerFactory.getSecurityManager(PrivilegeUtility.class);
		} catch (SMException e) {
			logger.error(e.getStackTrace());
		}
	}
	/**
	 * This method creates protection elements corresponding to protection
	 * objects passed and associates them with static as well as dynamic
	 * protection groups that are passed. It also creates user group, role,
	 * protection group mapping for all the elements in authorization data.
	 *
	 * @param authorizationData
	 *            Vector of SecurityDataBean objects
	 * @param protectionObjects
	 *            Set of AbstractDomainObject instances
	 * @param dynamicGroups
	 *            Array of dynamic group names
	 * @throws SMException sme
	 */
	public void insertAuthorizationData(List authorizationData, Set protectionObjects,
			String[] dynamicGroups) throws SMException
	{
		try
		{
			//Create protection elements corresponding to all protection
			Set protElems = createProtectionElementsFromProtectionObjects(protectionObjects);

			//Create user group role protection group and their mappings if
			if (authorizationData != null)
			{
				createUserGroupRoleProtectionGroup(authorizationData, protElems);
			}

			//Assigning protection elements to dynamic groups
			assignProtectionElementsToGroups(protElems, dynamicGroups);
		}
		catch (CSException exception)
		{
			String mess="The Security Service encountered a fatal exception.";
			throwException(exception, mess);
		}
	}

	/**
	 * This method creates protection elements from the protection objects
	 * passed and associate them with respective static groups they should be
	 * added to depending on their class name if the corresponding protection
	 * element does not already exist.
	 *
	 * @param protectionObjects objs
	 * @return set elems
	 * @throws CSException cse
	 */
	private Set createProtectionElementsFromProtectionObjects(Set<AbstractDomainObject> protectionObjects)
			throws CSException
	{
		ProtectionElement protElems;
		Set<ProtectionElement> pElements = new HashSet<ProtectionElement>();
		AbstractDomainObject protectionObject;
		Iterator<AbstractDomainObject> iterator;
		UserProvisioningManager upManager = getUserProvisioningManager();

		if (protectionObjects != null)
		{
			for (iterator = protectionObjects.iterator(); iterator.hasNext();)
			{
				protElems = new ProtectionElement();
				protectionObject = (AbstractDomainObject) iterator.next();
				protElems.setObjectId(protectionObject.getObjectId());
				populateProtectionElement(protElems, protectionObject,
						upManager);
				pElements.add(protElems);
			}
		}
		return pElements;
	}

	/**
	 * This method creates user group, role, protection group mappings in
	 * database for the passed authorizationData. It also adds protection
	 * elements to the protection groups for which mapping is made. For each
	 * element in authorization Data passed: User group is created and users are
	 * added to user group if one does not exist by the name passed. Similarly
	 * Protection Group is created and protection elements are added to it if
	 * one does not exist. Finally user group and protection group are
	 * associated with each other by the role they need to be associated with.
	 * If no role exists by the name an exception is thrown and the
	 * corresponding mapping is not created
	 *
	 * @param authorizationData list
	 * @param protElems elems
	 * @throws CSException cse
	 * @throws SMException sme
	 */
	private void createUserGroupRoleProtectionGroup(List authorizationData, Set protElems)
			throws CSException, SMException
	{
		ProtectionGroup protectionGroup = null;
		SecurityDataBean bean;
		String[] roleIds = null;
		Group group=null;
		UserProvisioningManager upManager = getUserProvisioningManager();
		if (authorizationData != null)
		{
			for (int i = 0; i < authorizationData.size(); i++)
			{

				try
				{
					bean =
						(SecurityDataBean) authorizationData.get(i);
					group = getNewGroupObject(bean);
					group=getGroupObject(group);
					assignGroupToUsersInUserGroup(bean,group);
					protectionGroup = getNewProtectionGroupObj(
										bean);
					protectionGroup= addProtElementToGroup(protectionGroup,protElems);
					roleIds = new String[1];
					roleIds[0] = getRoleId(bean);
					upManager.assignGroupRoleToProtectionGroup(
							String.valueOf(protectionGroup.getProtectionGroupId()),
							String.valueOf(group.getGroupId()), roleIds);
				}
				catch (CSTransactionException ex)
				{
					StringBuffer mess= new StringBuffer
					("Error occured Assigned Group Role To Protection Group ")
					.append(protectionGroup.getProtectionGroupId()).append(' ')
					.append(group.getGroupId()).append(' ').append(roleIds);
					throwException(ex, mess.toString());
				}
			}
		}
	}

	/**
	 * @param bean SecurityDataBean
	 * @return String role id
	 * @throws SMException sme
	 * @throws CSException cse
	 */
	private String getRoleId(SecurityDataBean bean) throws SMException, CSException
	{
		Role role = new Role();
		role.setName(bean.getRoleName());
		RoleSearchCriteria criteria = new RoleSearchCriteria(role);
		List list = getObjects(criteria);
		return String.valueOf(((Role) list.get(0)).getId());
	}
	/**
	 * If Protection group already exists add protection elements to the group
	 * If the protection group does not already exist create the protection group 
	 * and add protection elements to it.
	 * @param protectionGroup pGroups
	 * @param protElems elems
	 * @return ProtectionGroup grp
	 * @throws CSException exc
	 */
	private ProtectionGroup addProtElementToGroup(ProtectionGroup protectionGroup,Set protElems)
				throws CSException
	{
		ProtectionGroup protGroup=protectionGroup;
		ProtectionGroupSearchCriteria searchCriteria = new ProtectionGroupSearchCriteria(
				protGroup);
		UserProvisioningManager upManager = getUserProvisioningManager();
		List<ProtectionGroup> list = upManager.getObjects(searchCriteria);
		if (null == list || list.size() <= 0)
		{
			protGroup.setProtectionElements(protElems);
			upManager.createProtectionGroup(protGroup);
		}
		else
		{
		protGroup = (ProtectionGroup) list.get(0);
		}
		return protGroup;
	}
	/**
	 * @param bean {@link SecurityDataBean}
	 * @return {@link ProtectionGroup}
	 * @throws CSException exc
	 */
	private ProtectionGroup getNewProtectionGroupObj(
			SecurityDataBean bean) throws CSException
	{
		ProtectionGroup protectionGroup;
		protectionGroup = new ProtectionGroup();
		protectionGroup
				.setApplication(getApplication(
						SecurityManagerPropertiesLocator.getInstance().
						getApplicationCtxName()));
		protectionGroup.setProtectionGroupName(bean
				.getProtGrpName());
		return protectionGroup;
	}

	/**
	 * @param userGroupRoleProtectionGroupBean bean
	 * @param group Group
	 * @throws SMException ex
	 */
	private void assignGroupToUsersInUserGroup(SecurityDataBean userGroupRoleProtectionGroupBean,
			Group group) throws SMException
	{
		User user;
		Set userGroup = userGroupRoleProtectionGroupBean.getGroup();
		for (Iterator it = userGroup.iterator(); it.hasNext();)
		{
			user = (User) it.next();
			assignAdditionalGroupsToUser(String.valueOf(user.getUserId()),
					new String[]{String.valueOf(group.getGroupId())});
		}
	}

	/**
	 * @param userGroupRoleProtectionGroupBean bean
	 * @return Group
	 * @throws CSException exc
	 */
	private Group getNewGroupObject(SecurityDataBean userGroupRoleProtectionGroupBean)
			throws CSException
	{
		Group group = new Group();
		group.setApplication(getApplication(SecurityManagerPropertiesLocator
				.getInstance().getApplicationCtxName()));
		group.setGroupName(userGroupRoleProtectionGroupBean.getGroupName());
		return group;
	}
	/**
	 * @param group group
	 * @return Group
	 * @throws CSException exc
	 * @throws SMException exc
	 */
	private Group getGroupObject(Group group) throws CSException, SMException
	{
		GroupSearchCriteria grpSrchCri = new GroupSearchCriteria(group);
		UserProvisioningManager upManager = getUserProvisioningManager();
		List<Group> list = upManager.getObjects(grpSrchCri);
		if (null == list || list.size() <= 0)
		{
			upManager.createGroup(group);
			list = getObjects(grpSrchCri);
		}
		return (Group) list.get(0);
	}

	/**
	 * This method assigns Protection Elements passed to the Protection group
	 * names passed.
	 *
	 * @param protElems pElems
	 * @param groups groups
	 */
	private void assignProtectionElementsToGroups(Set<ProtectionElement> protElems, String[] groups)
	{
		ProtectionElement protectionElement;
		Iterator<ProtectionElement> iterator;
		if (groups != null)
		{
			for (int i = 0; i < groups.length; i++)
			{
				for (iterator = protElems.iterator(); iterator.hasNext();)
				{
					protectionElement = (ProtectionElement) iterator.next();
					assignProtectionElementToGroup(protectionElement, groups[i]);
				}
			}
		}
	}

	/**
	 * @param protectionElement eElement
	 * @param protectionObject abstarctDomainObj
	 * @param upManager userProvManager
	 * @throws CSException exc
	 */
	private void populateProtectionElement(ProtectionElement protectionElement,
			AbstractDomainObject protectionObject, UserProvisioningManager upManager)
			throws CSException
	{
		try
		{
			protectionElement
					.setApplication(getApplication(SecurityManagerPropertiesLocator.getInstance().getApplicationCtxName()));
			protectionElement.setProtectionElementDescription(protectionObject.getClass().getName()
					+ " object");
			protectionElement.setProtectionElementName(protectionObject.getObjectId());

			String[] staticGroups = (String[]) edu.wustl.security.global.Constants.STATIC_PROTECTION_GROUPS_FOR_OBJECT_TYPES
					.get(protectionObject.getClass().getName());

			setProtectGroups(protectionElement, staticGroups);
			upManager.createProtectionElement(protectionElement);
		}
		catch (CSTransactionException ex)
		{
			String mess="Error occured while creating Potection Element "
				+ protectionElement.getProtectionElementName();
			logger.warn(mess,ex);
			throw new CSException(mess, ex);
		}

	}
	/**
	 * @param userId string
	 * @param groupIds array
	 * @throws SMException exc
	 */
	public void assignAdditionalGroupsToUser(String userId, String[] groupIds) throws SMException
	{
		securityManager.assignAdditionalGroupsToUser(userId, groupIds);
	}

	/**
	 * Returns list of objects corresponding to the searchCriteria passed.
	 *
	 * @param searchCriteria criteria for search
	 * @return List of resultant objects
	 * @throws SMException
	 *             if searchCriteria passed is null or if search results in no
	 *             results
	 * @throws CSException exc
	 */
	public List getObjects(SearchCriteria searchCriteria) throws SMException, CSException
	{
		return ProvisionManager.getInstance().getInstance().getObjects(searchCriteria) ;
	}

	/**
	 * @param protectionElement elemnt
	 * @param groupsName name
	 */
	private void assignProtectionElementToGroup(ProtectionElement protectionElement,
			String groupsName)
	{
		try
		{
			UserProvisioningManager upManager = getUserProvisioningManager();
			upManager.assignProtectionElement(groupsName, protectionElement
					.getObjectId());
		}
		catch (CSException e)
		{
			StringBuffer mess=new StringBuffer
			("The Security Service encountered an error while associating protection group:")
			.append(groupsName).append(" to protectionElement")
			.append(protectionElement.getProtectionElementName());
			logger.error(mess.toString());
		}
	}

	/**
	 * @param protectionElement element
	 * @param staticGroups groups
	 * @throws CSException exc
	 */
	private void setProtectGroups(ProtectionElement protectionElement, String[] staticGroups)
			throws CSException
	{
		ProtectionGroup protectionGroup;
		Set<ProtectionGroup> protectionGroups = null;
		ProtectionGroupSearchCriteria pgSearchCriteria;
		if (staticGroups != null)
		{
			protectionGroups = new HashSet<ProtectionGroup>();
			for (int i = 0; i < staticGroups.length; i++)
			{
				protectionGroup = new ProtectionGroup();
				protectionGroup.setProtectionGroupName(staticGroups[i]);
				pgSearchCriteria = new ProtectionGroupSearchCriteria(protectionGroup);
				try
				{
					List<ProtectionGroup> list = getObjects(pgSearchCriteria);
					protectionGroup = (ProtectionGroup) list.get(0);
					protectionGroups.add(protectionGroup);
				}
				catch (SMException sme)
				{
					logger.warn("Error occured while retrieving " + staticGroups[i]
							+ "  From Database: ",sme);
				}
			}
			protectionElement.setProtectionGroups(protectionGroups);
		}
	}
	/**
	 * 
	 * @param applicationName app Name
	 * @return Application
	 * @throws CSException exc
	 */
	public Application getApplication(String applicationName) throws CSException
	{
		Application application = new Application();
		application.setApplicationName(applicationName);
		ApplicationSearchCriteria appnSearchCri = new ApplicationSearchCriteria(
				application);
		application = (Application) getUserProvisioningManager().getObjects(
				appnSearchCri).get(0);
		return application;
	}

	/**
	 * Returns the UserProvisioningManager singleton object.
	 * 
	 * @return UserProvisioningManager instance
	 * @throws CSException exc
	 */
	public UserProvisioningManager getUserProvisioningManager() throws CSException
	{
		return ProvisionManager.getInstance().getInstance().getUserProvisioningManager();
	}

	/**
	 * Returns the Authorization Manager for the caTISSUE Core. This method follows 
	 * the singleton pattern so that only one AuthorizationManager is created.
	 * @return AuthorizationManager
	 * @throws CSException common security exception
	 */
	protected AuthorizationManager getAuthorizationManager() throws CSException
	{
		return ProvisionManager.getInstance().getInstance().getAuthorizationManager();
	}

	/**
	 * This method returns the User object from the database for the passed
	 * User's Login Name. If no User is found then null is returned.
	 *
	 * @param loginName Login name of the user
	 * @return User user
	 * @throws SMException exc
	 */
	public User getUser(String loginName) throws SMException
	{
		return securityManager.getUser(loginName);
	}

	/**
	 * Returns the User object for the passed User id.
	 *
	 * @param userId -
	 *            The id of the User object which is to be obtained
	 * @return The User object from the database for the passed User id
	 * @throws SMException
	 *             if the User object is not found for the given id
	 */
	public User getUserById(String userId) throws SMException
	{
		return securityManager.getUserById(userId);
	}

	/**
	 * This method returns role corresponding to the rolename passed.
	 *
	 * @param roleName name of the role
	 * @return Role role
	 * @throws CSException csex
	 * @throws SMException exc
	 */
	public Role getRole(String roleName) throws CSException, SMException
	{
		if (roleName == null)
		{
			String mess = "Role name passed is null";
			throwException(null, mess);
		}

		//Search for role by the name roleName
		Role role = new Role();
		role.setName(roleName);
		role.setApplication(getApplication(SecurityManagerPropertiesLocator.
				getInstance().getApplicationCtxName()));
		RoleSearchCriteria roleSearchCriteria= new RoleSearchCriteria(role);
		List<Role> list;
		try
		{
			list = getObjects(roleSearchCriteria);
			role = (Role) list.get(0);
		}
		catch (SMException e)
		{
			String mess = "Role not found by name " + roleName;
			throwException(e, mess);
		}
		return role;
	}
	/**
	 * given a role id it returns privileges
	 * @param roleId id
	 * @return set of privs
	 * @throws CSException exc
	 */
	public Set<Privilege> getRolePrivileges(String roleId) throws CSException
	{
		return getUserProvisioningManager().getPrivileges(roleId);
	}

	/**
	 * This method returns protection group corresponding to the naem passed. In
	 * case it does not exist it creates one and returns that.
	 * 
	 * @param pgName string
	 * @throws CSException exception
	 * @throws SMException exception
	 * @return ProtectionGroup grp
	 */
	public ProtectionGroup getProtectionGroup(String pgName) throws CSException,
			 SMException
	{
		if (pgName == null)
		{
			logger.debug("pgName passed is null");
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage("No protectionGroup of name null " );
			throw new SMException(defaultErrorKey, null,null);
		}

		//Search for Protection Group of the name passed
		ProtectionGroupSearchCriteria pgSearchCriteria;
		ProtectionGroup protectionGroup;
		protectionGroup = new ProtectionGroup();
		protectionGroup.setProtectionGroupName(pgName);
		pgSearchCriteria = new ProtectionGroupSearchCriteria(protectionGroup);
		UserProvisioningManager upManager = null;
		List<ProtectionGroup> list;
		try
		{
			upManager = getUserProvisioningManager();
			list = getObjects(pgSearchCriteria);
		}
		catch (SMException e)
		{
			logger.debug("Protection Group not found by name " + pgName);
			upManager.createProtectionGroup(protectionGroup);
			list = getObjects(pgSearchCriteria);
		}
		protectionGroup = (ProtectionGroup) list.get(0);
		return protectionGroup;
	}

	/**
	 * This method assigns additional protection Elements identified by
	 * protectionElementIds to the protection Group identified by
	 * pgName
	 * 
	 * @param pgName pgName
	 * @param objectType Class
	 * @param objectIds objectIds
	 * @throws SMException SMException
	 */
	public void assignProtectionElements(String pgName, Class objectType,
			Long[] objectIds) throws SMException
			{
		try
		{
			checkForSufficientParams(pgName, objectType, objectIds);
			UserProvisioningManager upManager = getUserProvisioningManager();
			for (int i = 0; i < objectIds.length; i++)
			{
				upManager.assignProtectionElement
				(pgName, objectType.getName()+ "_" + objectIds[i]);
			}
		}
		catch (CSTransactionException txex) //thrown when association
		{
			logger.debug("Exception:" + txex.getMessage(),txex);
			throwException(txex, txex.getMessage());
		}
		catch (CSException csex)
		{
			String mess="Could not assign Protection elements to protection group";
			throwException(csex, mess);
		}
			}

	/**
	 * This method assigns user identified by userId, roles identified by roles
	 * on protectionGroup
	 *
	 * @param userId user id
	 * @param roles roles
	 * @param protectionGroup operation
	 * @param assignOperation boolean
	 * @throws SMException exception
	 */
	public void assignUserRoleToProtectionGroup(Long userId, Set roles,
			ProtectionGroup protectionGroup, boolean assignOperation) throws SMException
	{
		if (userId == null || roles == null || protectionGroup == null)
		{
			logger.debug("One or more parameters are null");
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage("Could not assign user role to protection group");
			throw new SMException(defaultErrorKey, null,null);
		}
		try
		{
			UserProvisioningManager upManager = getUserProvisioningManager();
			Set aggregatedRoles = getAllRolesOnProtGroup(userId, protectionGroup,
					upManager);
			aggregatedRoles = addRemoveRoles(roles, assignOperation, aggregatedRoles);
			String[] roleIds = getRoleIds(aggregatedRoles);
			upManager.assignUserRoleToProtectionGroup(String.valueOf(userId),
					roleIds, String.valueOf(protectionGroup.getProtectionGroupId()));
		}
		catch (CSException csex)
		{
			logger.debug("Could not assign user role to protection group", csex);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage("Could not assign user role to protection group");
			throw new SMException(defaultErrorKey, csex,null);
		}
	}

	/**
	 * get all the roles that user has on this protection group.
	 * @param userId user id
	 * @param protectionGroup protGrp
	 * @param upManager manager class
	 * @return set of roles
	 * @throws CSObjectNotFoundException exception
	 */
	private Set getAllRolesOnProtGroup(Long userId, ProtectionGroup protectionGroup,
			UserProvisioningManager upManager) throws CSObjectNotFoundException
	{
		Set pgRoleContextSet = upManager.getProtectionGroupRoleContextForUser(String.valueOf(userId));
		return getAggregatedRoles(protectionGroup, pgRoleContextSet);
	}

	/**
	 * This method returns array of rile id.
	 * @param aggregatedRoles Set of roles
	 * @return array of role ids
	 */
	private String[] getRoleIds(Set<Role> aggregatedRoles)
	{
		String[] roleIds = null;
		roleIds = new String[aggregatedRoles.size()];
		Iterator<Role> roleIt = aggregatedRoles.iterator();

		for (int i = 0; roleIt.hasNext(); i++)
		{
			roleIds[i] = String.valueOf(((Role) roleIt.next()).getId());
		}
		return roleIds;
	}

	/**
	 * @param roles roles.
	 * @param assignOperation operation
	 * @param aggrRoles list of roles
	 * @return set of roles
	 */
	private Set addRemoveRoles(Set roles, boolean assignOperation, Set aggrRoles)
	{
		Set aggregatedRoles = aggrRoles;

		// if the operation is assign, add the roles to be assigned.
		if (assignOperation == Constants.PRIVILEGE_ASSIGN)
		{
			aggregatedRoles.addAll(roles);
		}
		else
		// if the operation is de-assign, remove the roles to be de-assigned.
		{
			Set newaggregateRoles = removeRoles(aggregatedRoles, roles);
			aggregatedRoles = newaggregateRoles;
		}
		return aggregatedRoles;
	}
	/**
	 * Removes roles
	 * @param fromSet src
	 * @param toSet dest 
	 * @return set of roles
	 */
	private Set removeRoles(Set<Role> fromSet, Set<Role> toSet)
	{
		Set<Role> differnceRoles = new HashSet<Role>();
		Iterator<Role> fromSetiterator = fromSet.iterator();
		while (fromSetiterator.hasNext())
		{
			Role role1 = (Role) fromSetiterator.next();

			Iterator<Role> toSetIterator = toSet.iterator();
			while (toSetIterator.hasNext())
			{
				Role role2 = (Role) toSetIterator.next();

				if (!role1.getId().equals(role2.getId()))
				{
					differnceRoles.add(role1);
				}
			}
		}
		return differnceRoles;
	}

	/**
	 * @param pgName string
	 * @param objectType Class
	 * @param objectIds objectIds
	 * @throws SMException exception
	 */
	public void deAssignProtectionElements(String pgName, Class objectType,
			Long[] objectIds) throws SMException
			{
		checkForSufficientParams(pgName, objectType, objectIds);
		try
		{
			UserProvisioningManager upManager = getUserProvisioningManager();
			for (int i = 0; i < objectIds.length; i++)
			{
				upManager.deAssignProtectionElements(pgName,
						objectType.getName() + "_" + objectIds[i]);

			}
		}
		catch (CSTransactionException txex) //thrown when no association exists
		{
			String mess="Could not deassign Protection elements to protection group"+txex.getMessage();
			throwException(txex, mess);
		}
		catch (CSException csex)
		{
			String mess="Could not deassign Protection elements to protection group"+csex.getMessage();
			throwException(csex, mess);
		}
			}
	/**
	 * Called when we need to throw SMException
	 * @param exc exception
	 * @param mess message to be shown on error
	 * @throws SMException exception
	 */
	public void throwException(Exception exc, String mess)
			throws SMException {
		logger.debug(mess, exc);
		ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
		defaultErrorKey.setErrorMessage(mess);
		throw new SMException(defaultErrorKey, exc,null);
	}
	/**
	 * Checks for sufficient params
	 * @param pgName string
	 * @param objectType class
	 * @param objectIds list
	 * @throws SMException exception
	 */
	private void checkForSufficientParams(String pgName, Class objectType,
			Long[] objectIds) throws SMException {
		if (pgName == null || objectType == null || objectIds == null)
		{
			String mess="Cannot disassign protection elements. One of the parameters is null.";
			throwException(null, mess);
		}
	}
	/**
	 * 
	 * @param roleID string
	 * @return groupid string
	 */
	public String getGroupIdForRole(String roleID)
	{
		return securityManager.getGroupIdForRole(roleID);
	}

	/**
	 * This method assigns user group identified by groupId, roles identified by
	 * roles on protectionGroup
	 *
	 * @param groupId id
	 * @param roles roles
	 * @param protectionGroup protectionGroup
	 * @param assignOperation boolean
	 * @throws SMException Exception
	 */
	public void assignGroupRoleToProtectionGroup(Long groupId, Set roles,
			ProtectionGroup protectionGroup, boolean assignOperation) throws SMException
	{
		checkForSufficientParams(groupId, roles, protectionGroup);
		Set protectionGroupRoleContextSet = null;
		ProtectionGroupRoleContext pgRoleContext = null;

		Set aggregatedRoles = new HashSet();
		try
		{
			UserProvisioningManager upManager = getUserProvisioningManager();
			try
			{
				protectionGroupRoleContextSet = upManager
						.getProtectionGroupRoleContextForGroup(String.valueOf(groupId));
			}
			catch (CSObjectNotFoundException e)
			{
				logger.debug("Could not find Role Context for the Group: " + e.toString());
			}
			if (pgRoleContext != null)
			{
				aggregatedRoles=getAggregatedRoles(protectionGroup, protectionGroupRoleContextSet);
			}
			aggregatedRoles = addRemoveRoles(roles, assignOperation, aggregatedRoles);
			String[] roleIds = getRoleIds(aggregatedRoles);
			upManager.assignGroupRoleToProtectionGroup(String.valueOf(protectionGroup
					.getProtectionGroupId()), String.valueOf(groupId), roleIds);

		}
		catch (CSException csex)
		{
			String mess = "Could not assign user role to protection group";
			throwException(csex, mess);
		}
	}
	/**
	 * @param groupId id
	 * @param roles roles
	 * @param protectionGroup group
	 * @throws SMException exc
	 */
	private void checkForSufficientParams(Long groupId, Set roles,
			ProtectionGroup protectionGroup) throws SMException {
		if (groupId == null || roles == null || protectionGroup == null)
		{
			String mess="One or more parameters are null";
			throwException(null, mess);
		}
	}

	/**
	 * @param protectionGroup group obj
	 * @param protectionGroupRoleContextSet set
	 * @return set of roles
	 */
	private Set getAggregatedRoles(ProtectionGroup protectionGroup,Set protectionGroupRoleContextSet)
	{
		ProtectionGroupRoleContext protectionGroupRoleContext;
		Set aggregatedRoles = new HashSet();
		Iterator iterator = protectionGroupRoleContextSet.iterator();
		while (iterator.hasNext())
		{
			protectionGroupRoleContext = (ProtectionGroupRoleContext) iterator.next();
			if (protectionGroupRoleContext.getProtectionGroup().getProtectionGroupId()
					.equals(protectionGroup.getProtectionGroupId()))
			{
				aggregatedRoles.addAll(protectionGroupRoleContext.getRoles());
				break;
			}
		}
		return aggregatedRoles;
	}
	/**
	 * 
	 * @param privilegeId priv Id
	 * @return Privilege priv
	 * @throws CSException exc
	 */
	public Privilege getPrivilegeById(String privilegeId) throws CSException
	{
		return getUserProvisioningManager().getPrivilegeById(privilegeId);

	}
	
	/**
	 * Getting Appropriate Role, role name is generated as {privilegeName}_ONLY.
	 * @param privilegeName name
	 * @return Role role
	 * @throws CSException CSException
	 * @throws SMException SMException
	 */
	public Role getRoleByPrivilege(String privilegeName) throws CSException,SMException
	{
		String roleName;
		if (privilegeName.equals(Permissions.READ))
		{
			roleName = Permissions.READ_DENIED;
		}
		else
		{
			roleName = privilegeName + "_ONLY";
		}
		return getRole(roleName);
	}
	/**
	 * gets protection group name
	 * @param objectId id
	 * @param objectType type
	 * @return String name
	 * @throws ClassNotFoundException excpetion
	 */
	public static String getProtectionGroupName(Long objectId,Class objectType) throws ClassNotFoundException {
		String protGrName = null;
		CSMGroupLocator locator = new CSMGroupLocator();
		if (objectType.getName().equals(Constants.COLLECTION_PROTOCOL_CLASS_NAME))
		{
			protGrName = locator.getPGName(objectId,Class.forName(
					Constants.COLLECTION_PROTOCOL_CLASS_NAME));
		}
		else if (objectType.getName().equals(Constants.DISTRIBUTION_PROTOCOL_CLASS_NAME))
		{
			protGrName = locator.getPGName(objectId,Class.forName(
					Constants.DISTRIBUTION_PROTOCOL_CLASS_NAME));
		}
		return protGrName;
	}
	/*public static final String getDistributionProtocolPIGroupName(Long identifier)
	{
	    if(identifier == null)
	    {
	        return "PI_DISTRIBUTION_PROTOCOL_";
	    }
	    return "PI_DISTRIBUTION_PROTOCOL_"+identifier;
	}*/
}
