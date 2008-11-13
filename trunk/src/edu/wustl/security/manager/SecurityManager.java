/**
 *<p>Title: </p>
 *<p>Description:  </p>
 *<p>Copyright: (c) Washington University, School of Medicine 2004</p>
 *<p>Company: Washington University, School of Medicine, St. Louis.</p>
 *@author Aarti Sharma
 *@version 1.0
 */

package edu.wustl.security.manager;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import edu.wustl.common.domain.AbstractDomainObject;
import edu.wustl.common.exception.ErrorKey;
import edu.wustl.common.query.AbstractClient;
import edu.wustl.common.util.Permissions;
import edu.wustl.common.util.XMLPropertyHandler;
import edu.wustl.common.util.global.Constants;
import edu.wustl.common.util.global.TextConstants;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.beans.RoleGroupDetailsBean;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.exception.SMTransactionException;
import edu.wustl.security.global.ProvisionManager;
import edu.wustl.security.locator.RoleGroupLocator;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
import gov.nih.nci.security.AuthenticationManager;
import gov.nih.nci.security.AuthorizationManager;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.domainobjects.Group;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.ProtectionGroup;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.dao.GroupSearchCriteria;
import gov.nih.nci.security.dao.SearchCriteria;
import gov.nih.nci.security.dao.UserSearchCriteria;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.exceptions.CSObjectNotFoundException;
import gov.nih.nci.security.exceptions.CSTransactionException;

/**
 * <p>
 * Title:
 * </p>
 * <p>
 * Description:
 * </p>
 * <p>
 * Copyright: (c) Washington University, School of Medicine 2005
 * </p>
 * <p>
 * Company: Washington University, School of Medicine, St. Louis.
 * </p>
 * 
 * @author Aarti Sharma
 * @version 1.0
 */

public class SecurityManager implements Permissions,ISecurityManager
{

	/**
	 * logger Logger - Generic logger.
	 */
	protected static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);



	private Class requestingClass = null;

	public static final String ADMIN_GROUP = "ADMIN_GROUP";
	public static final String SUPER_ADMIN_GROUP = "SUPER_ADMIN_GROUP";
	public static final String SUPERVISOR_GROUP = "SUPERVISOR_GROUP";
	public static final String TECHNICIAN_GROUP = "TECHNICIAN_GROUP";
	public static final String PUBLIC_GROUP = "PUBLIC_GROUP";

	public static final String CLASS_NAME = "CLASS_NAME";

	public static final String TABLE_NAME = "TABLE_NAME";

	public static final String TABLE_ALIAS_NAME = "TABLE_ALIAS_NAME";

	/**
	 * Returns true or false depending on the person gets authenticated or not.
	 * @param requestingClass
	 * @param loginName login name
	 * @param password password
	 * @return
	 * @throws CSException
	 */
	
	public boolean login(final String loginName,final String password) throws SMException
	{
		boolean loginSuccess = false;
		try
		{
			AuthenticationManager authMngr = ProvisionManager.getInstance().getAuthenticationManager();
			loginSuccess = authMngr.login(loginName, password);
		}
		catch (CSException exception)
		{
			StringBuffer mesg=new StringBuffer("Authentication fails for user")
			.append(loginName).append("requestingClass:").append(requestingClass);
			logger.debug(mesg);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg.toString());
			throw new SMException(defaultErrorKey,exception,null);
		}
		return loginSuccess;
	}

	/**
	 * This method creates a new User in the database based on the data passed
	 * 
	 * @param user
	 *            user to be created
	 * @throws SMTransactionException
	 *             If there is any exception in creating the User
	 */
	public void createUser(User user) throws SMTransactionException
	{
		try
		{
			ProvisionManager.getInstance().getUserProvisioningManager().createUser(user);
		}
		catch (CSTransactionException exception)
		{
			logger.debug("Unable to create user "+user.getEmailId());
			String mesg = "Unable to create user "+user.getEmailId();
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMTransactionException(defaultErrorKey,exception,null);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to create user:"+user.getEmailId(), exception);
		}
	}

	/**
	 * This method returns the User object from the database for the passed
	 * User's Login Name. If no User is found then null is returned
	 *
	 * @param loginName Login name of the user
	 * @return User
	 * @throws SMException
	 */
	public User getUser(final String loginName) throws SMException
	{
		try
		{
			return ProvisionManager.getInstance().getAuthorizationManager().getUser(loginName);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get user: "+loginName,exception);
			String mesg = "Unable to get user: "+loginName;
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);
		}
	}
	
	/**
	 * 
	 */
	public void removeUser(final String userId) throws SMException
	{
		try
		{
			ProvisionManager.getInstance().getUserProvisioningManager().removeUser(userId);
		}
		catch (CSTransactionException ex)
		{
			logger.debug("Unable to get user: Exception: " + ex.getMessage());
			String mesg = "Failed to find this user with userId:" + userId;
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMTransactionException(defaultErrorKey,ex,null);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to obtain Authorization Manager: Exception: " + exception.getMessage());
			String mesg = "Failed to find this user with userId:" + userId;
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);
		}
	}

	/**
	 * This method returns Vactor of all the role objects defined for the
	 * application from the database
	 * 
	 * @return @throws
	 *         SMException
	 */
	public List<Role> getRoles() throws SMException
	{
		List<Role> roles = new ArrayList<Role>();
		UserProvisioningManager upManager = null;
		try
		{
			upManager = ProvisionManager.getInstance().getUserProvisioningManager();
			List<String> roleIdList = RoleGroupLocator.getInstance().getAllRoleIds();
			for (String roleId : roleIdList) {
				roles.add(upManager.getRoleById(roleId));
			}
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get roles: Exception: ",exception);
			
			String mesg = "Unable to get roles: Exception:  ";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);
		}
		return roles;
	}

	/**
	 * Assigns a Role to a User
	 * 
	 * @param userName - the User Name to to whom the Role will be assigned
	 * @param roleID -	The id of the Role which is to be assigned to the user
	 * @throws SMException
	 */
	public void assignRoleToUser(final String userID, final String roleID) throws SMException
	{
		try
		{
			UserProvisioningManager upManager = ProvisionManager.getInstance().getUserProvisioningManager();
			User user = upManager.getUserById(userID);

			//Remove user from any other role if he is assigned some
			String userId = String.valueOf(user.getUserId());
			List<String> allGroupIds = RoleGroupLocator.getInstance().getAllGroupIds();
			for (String grpId : allGroupIds) {
				upManager.removeUserFromGroup(grpId, userId);
			}
			//Add user to corresponding group
			String groupId = getGroupIdForRole(roleID);
			if (groupId == null)
			{
				logger.info(" User assigned no role");
			}
			else
			{
				assignAdditionalGroupsToUser(userId,
						new String[]{groupId});
				logger.info(" User assigned role:" + groupId);
			}

		}
		catch (CSException exception)
		{
			logger.debug("UNABLE TO ASSIGN ROLE TO USER: Exception: " + exception.getMessage());
			String mesg = "UNABLE TO ASSIGN ROLE TO USER: Exception: ";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);
		}
	}

	public String getGroupIdForRole(String roleID)
	{
		/*String roleName=null;
		String groupType=null;*/
		
		String roleGroupId=null;
		RoleGroupDetailsBean sampleBean = new RoleGroupDetailsBean();
		sampleBean.setRoleId(roleID);

		RoleGroupDetailsBean requiredBean = getRequiredBean(sampleBean);
		if(requiredBean == null)
		{
			logger.debug("role corresponds to no group");
		}
		else
		{
			roleGroupId = requiredBean.getGroupId();
		}
		return roleGroupId;
	}

	public Role getUserRole(long userID) throws SMException
	{
		Set<Group> groups;
		UserProvisioningManager upManager = null;
		Role role = null;
		try
		{
			upManager = ProvisionManager.getInstance().getUserProvisioningManager();
			groups = upManager.getGroups(String.valueOf(userID));
			role = getRole(groups, upManager);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get roles: Exception: " + exception.getMessage(),exception);
			String mesg = "Unable to get roles: Exception:  ";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);
		}
		return role;
	}

	

	/**
	 * Name : Virender Mehta
	 * Reviewer: Sachin Lale
	 * Bug ID: 3842
	 * Patch ID: 3842_2
	 * See also: 3842_1
	 * Description: This function will return the Role name(Administrator, Scientist, Technician, Supervisor )
	 * @param userID
	 * @return Role Name
	 * @throws SMException
	 */
	public String getRoleName(long userID) throws SMException
	{
		String role=TextConstants.EMPTY_STRING;
		try
		{
			UserProvisioningManager upManager = ProvisionManager.getInstance().getUserProvisioningManager();
			Set groups = upManager.getGroups(String.valueOf(userID));
			Iterator iter = groups.iterator();
			while (iter.hasNext())
			{
				Group group = (Group) iter.next();
				if (group.getApplication().getApplicationName().equals(SecurityManagerPropertiesLocator.getInstance().getApplicationCtxName()))
				{
					RoleGroupDetailsBean sampleBean = new RoleGroupDetailsBean();
					sampleBean.setGroupName(group.getGroupName());
					RoleGroupDetailsBean requiredBean = getRequiredBean(sampleBean);
					role = requiredBean.getRoleName();
				}
			}
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get roles: Exception: " + exception.getMessage(),exception);
			String mesg = "Unable to get roles: Exception: ";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);
		}
		return role;
	}

	/**
	 * Modifies an entry for an existing User in the database based on the data
	 * passed.
	 *
	 * @param user -the User object that needs to be modified in the database
	 * @throws SMException if there is any exception in modifying the User in the database
	 */
	public void modifyUser(User user) throws SMException
	{
		try
		{
			ProvisionManager.getInstance().getUserProvisioningManager().modifyUser(user);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to modify user: Exception: " + exception.getMessage(),exception);
			String mesg = "Unable to modify user: Exception:  ";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);
		}
	}

	/**
	 * Returns the User object for the passed User id.
	 *
	 * @param userId -The id of the User object which is to be obtained
	 * @return The User object from the database for the passed User id
	 * @throws SMException -if the User object is not found for the given id
	 */
	public User getUserById(String userId) throws SMException
	{
		try
		{
			return ProvisionManager.getInstance().getUserProvisioningManager().getUserById(userId);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get user by Id for : "+userId,exception);
			String mesg = "Unable to get user by Id for : ";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);		
		}
	}

	/**
	 * @throws SMException
	 *  
	 */
	public List getUsers() throws SMException
	{
		try
		{
			User user = new User();
			SearchCriteria searchCriteria = new UserSearchCriteria(user);
			return ProvisionManager.getInstance().getUserProvisioningManager().getObjects(searchCriteria);
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get all users: Exception: " + exception.getMessage());
			String mesg = "Unable to get all users: Exception: ";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);	
		}
	}



	public void assignUserToGroup(String userGroupname, String userId) throws SMException
	{
		checkForSufficientParamaters(userGroupname, userId);
		try
		{
			Group group = getUserGroup(userGroupname);
			if (group == null)
			{
				logger.debug("No user group with name " + userGroupname + " is present");
			}
			else
			{
				String[] groupIds = {group.getGroupId().toString()};
				assignAdditionalGroupsToUser(userId, groupIds);
			}
		}
		catch (CSException exception)
		{
			String mess="The Security Service encountered a fatal exception.";
			logger.fatal(mess, exception);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mess);
			throw new SMException(defaultErrorKey,exception,null);		
		}
	}
	

	public void removeUserFromGroup(String userGroupname, String userId) throws SMException
	{
		checkForSufficientParamaters(userGroupname, userId);
		try
		{
			UserProvisioningManager upManager = ProvisionManager.getInstance().getUserProvisioningManager();
			Group group = getUserGroup(userGroupname);
			if (group == null)
			{
				logger.debug("No user group with name " + userGroupname + " is present");
			}
			else
			{
				upManager.removeUserFromGroup(group.getGroupId().toString(), userId);
			}
		}
		catch (CSException ex)
		{
			String mess="The Security Service encountered a fatal exception.";
			logger.fatal(mess, ex);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mess);
			throw new SMException(defaultErrorKey,ex,null);	
		}
	}

	/**
	 * Assigns additional groups to user
	 * @param userId string userId
	 * @param groupIds string[]
	 * @throws SMException exception
	 */
	public void assignAdditionalGroupsToUser(String userId, String[] groupIds) throws SMException
	{
		checkForSufficientParams(userId, groupIds);
		
		Group group = null;
		try
		{
			UserProvisioningManager upManager = ProvisionManager.getInstance().getUserProvisioningManager();
			Set conGrpIds = addAllGroups(userId, groupIds, upManager);
			String[] finalUserGroupIds = new String[conGrpIds.size()];
			Iterator iter = conGrpIds.iterator();
			for (int i = 0; iter.hasNext(); i++)
			{
				finalUserGroupIds[i] = (String) iter.next();
			}
			//Setting groups for user and updating it
			upManager.assignGroupsToUser(userId, finalUserGroupIds);
		}
		catch (CSException exception)
		{
			String mesg="The Security Service encountered a fatal exception.";
			logger.fatal(mesg, exception);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,exception,null);	
		}
	}

	/**
	 * Adds existing and required groups together in a Set.
	 * @param userId
	 * @param groupIds
	 * @param upManager
	 * @return
	 * @throws CSObjectNotFoundException
	 */
	private Set<String> addAllGroups(String userId, String[] groupIds,
			UserProvisioningManager upManager) throws CSObjectNotFoundException {
		Group group;
		Set<Group> conGrps = upManager.getGroups(userId);
		Set<String> conGrpIds = new HashSet<String>();	
		if (null != conGrps)
		{
			Iterator<Group> iter = conGrps.iterator();
			while (iter.hasNext())
			{
				group = iter.next();
				Long groupId = group.getGroupId();
				conGrpIds.add(String.valueOf(groupId));
			}
		}
		//Consolidating all the Groups
		for (int i = 0; i < groupIds.length; i++)
		{
			conGrpIds.add(groupIds[i]);
		}
		return conGrpIds;
	}

	/**
	 * @param userId
	 * @param groupIds
	 * @throws SMException
	 */
	private void checkForSufficientParams(String userId, String[] groupIds)
			throws SMException {
		if (userId == null || groupIds == null || groupIds.length < 1)
		{
			String mesg=" Null or insufficient Parameters passed";
			logger.debug(mesg);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,null,null);	
		}
	}
	/**
	 * 
	 */
	public boolean isAuthorized(String userName, String objectId, String privilegeName)
	throws SMException
	{
		try
		{
			return ProvisionManager.getInstance().getAuthorizationManager().checkPermission(userName, objectId,privilegeName);
		}
		catch (CSException e)
		{
			logger.debug( e.getMessage(),e);
			String mesg="in isAuthorized";
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,e,null);	
		}
	}

	public boolean checkPermission(String userName, String objectType, String objectIdentifier,
			String privilegeName) throws SMException
			{
		boolean isAuthorized=true;
		if (Boolean.parseBoolean(XMLPropertyHandler.getValue(Constants.ISCHECKPERMISSION)))
		{
			try
			{
				isAuthorized = ProvisionManager.getInstance().getAuthorizationManager().checkPermission(userName,
						objectType + "_" + objectIdentifier, privilegeName);
			}
			catch (CSException exception)
			{
				logger.debug("Unable tocheck permissionn" ,exception);
				String mesg="Unable to check permission";
				ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
				defaultErrorKey.setErrorMessage(mesg);
				throw new SMException(defaultErrorKey,exception,null);	
			}
		}
		return isAuthorized;
			}

	/**
	 * This method returns name of the Protection groupwhich consists of obj as
	 * Protection Element and whose name consists of string nameConsistingOf.
	 * 
	 * @param obj
	 * @param nameConsistingOf
	 * @return @throws
	 *         SMException
	 */
	public String getProtectionGroupByName(AbstractDomainObject obj, String nameConsistingOf)
	throws SMException
	{
		Set protectionGroups;
		ProtectionGroup protectionGroup;
		ProtectionElement protectionElement;
		String name = null;
		String protElemName = obj.getObjectId();
		try
		{
			AuthorizationManager authManager = ProvisionManager.getInstance().getAuthorizationManager();
			protectionElement = authManager.getProtectionElement(protElemName);
			protectionGroups = authManager.getProtectionGroups(protectionElement
					.getProtectionElementId().toString());
			Iterator<ProtectionGroup> iter = protectionGroups.iterator();
			while (iter.hasNext())
			{
				protectionGroup = (ProtectionGroup) iter.next();
				name = protectionGroup.getProtectionGroupName();
				if (name.indexOf(nameConsistingOf) != -1)
				{
					break;
				}
			}
		}
		catch (CSException exception)
		{
			String mess= new StringBuffer("Unable to get protection group by name")
			.append(nameConsistingOf).append(" for Protection Element ")
			.append(protElemName).toString();
			logger.debug(mess, exception);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mess);
			throw new SMException(defaultErrorKey,exception,null);	
		}
		return name;

	}

	/**
	 * This method returns name of the Protection groupwhich consists of obj as
	 * Protection Element and whose name consists of string nameConsistingOf.
	 * 
	 * @param obj
	 * @param nameConsistingOf
	 * @return @throws SMException
	 */
	public String[] getProtectionGroupByName(AbstractDomainObject obj) throws SMException
	{
		Set<ProtectionGroup> protectionGroups;
		Iterator<ProtectionGroup> iter;
		ProtectionGroup protectionGroup;
		ProtectionElement protectionElement;
		String[] names = null;
		String protElemName = obj.getObjectId();
		try
		{
			AuthorizationManager authManager = ProvisionManager.getInstance().getAuthorizationManager();
			protectionElement = authManager.getProtectionElement(protElemName);
			protectionGroups = authManager.getProtectionGroups(protectionElement
					.getProtectionElementId().toString());
			iter = protectionGroups.iterator();
			names = new String[protectionGroups.size()];
			int cnt = 0;
			while (iter.hasNext())
			{
				protectionGroup = (ProtectionGroup) iter.next();
				names[cnt++] = protectionGroup.getProtectionGroupName();

			}
		}
		catch (CSException exception)
		{
			String mess="Unable to get protection group for Protection Element "+ protElemName;
			logger.debug(mess,exception);
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mess);
			throw new SMException(defaultErrorKey,exception,null);	
		}
		return names;

	}

	/**
	 * Returns name value beans corresponding to all privileges that can be
	 * assigned for Assign Privileges Page.
	 * 
	 * @param roleName role name of user logged in
	 * @return
	 *//*
	public List<NameValueBean> getPrivilegesForAssignPrivilege(String roleName)
	{
		List<NameValueBean> privileges = new Vector();
		NameValueBean nameValueBean;
		nameValueBean = new NameValueBean(Permissions.READ, Permissions.READ);
		privileges.add(nameValueBean);
		//Use privilege only provided to Administrtor in Assing privileges page.
		if (roleName.equals(Constants.ADMINISTRATOR))
		{
			nameValueBean = new NameValueBean(Permissions.USE, Permissions.USE);
			privileges.add(nameValueBean);
		}
		return privileges;
	}
*/
	/**
	 * This method returns NameValueBeans for all the objects of type objectType
	 * on which user with identifier userID has privilege ASSIGN_ <
	 * <privilegeName>>.
	 * 
	 * @param userID
	 * @param objectType
	 * @param privilegeName
	 * @return @throws
	 *         SMException thrown if any error occurs while retreiving
	 *         ProtectionElementPrivilegeContextForUser
	 *//*
	private Set<NameValueBean> getObjectsForAssignPrivilege(Collection privilegeMap, String objectType,
			String privilegeName) throws SMException
			{
		Set<NameValueBean> objects = new HashSet<NameValueBean>();
		NameValueBean nameValueBean;
		ObjectPrivilegeMap objectPrivilegeMap;
		Collection privileges;
		Iterator iterator;
		String objectId;
		Privilege privilege;

		if (privilegeMap != null)
		{
			iterator = privilegeMap.iterator();
			while (iterator.hasNext())
			{
				objectPrivilegeMap = (ObjectPrivilegeMap) iterator.next();
				objectId = objectPrivilegeMap.getProtectionElement().getObjectId();
				if (objectId.indexOf(objectType + "_") != -1)
				{
					privileges = objectPrivilegeMap.getPrivileges();
					Iterator it = privileges.iterator();
					String name;
					while (it.hasNext())
					{
						privilege = (Privilege) it.next();
						if (privilege.getName().equals("ASSIGN_" + privilegeName))
						{
							name=objectId.substring(objectId.lastIndexOf('_') + 1);
							nameValueBean = new NameValueBean(name,name);
							objects.add(nameValueBean);
							break;
						}
					}
				}
			}
		}

		return objects;
			}*/

	/**
	 * This method returns name value beans of the object ids for types
	 * identified by objectTypes on which user can assign privileges identified
	 * by privilegeNames User needs to have ASSIGN_ {privilegeName}privilege
	 * on these objects to assign corresponding privilege on them identified by
	 * userID has.
	 *
	 * @param userID
	 * @param objectTypes
	 * @param privilegeNames
	 * @return @throws SMException
	 *//*
	public Set<NameValueBean> getObjectsForAssignPrivilege(String userID, String[] objectTypes,
			String[] privilegeNames) throws SMException
			{
		Set<NameValueBean> objects=null;

		try
		{
			User user = new User();
			user = getUserById(userID);
			if (objectTypes == null || privilegeNames == null ||user == null)
			{
				logger.debug(" User not found");
				objects = new HashSet<NameValueBean>();
			}
			else
			{
				objects=getAssignedPrivilege(objectTypes, privilegeNames, user);
			}
		}
		catch (CSException exception)
		{
			logger.debug("Unable to get objects: " ,exception);
			throw new SMException("Unable to get objects: ", exception);
		}
		return objects;

			}*/

	/**
	 * @param objectTypes
	 * @param privilegeNames
	 * @param objects
	 * @param user
	 * @throws CSException
	 *//*
	private Set<NameValueBean> getAssignedPrivilege(String[] objectTypes, String[] privilegeNames,
			User user) throws CSException
			{
		Set<NameValueBean> objects = new HashSet<NameValueBean>();
		Collection privilegeMap;
		List list;
		ProtectionElement protectionElement;
		ProtectionElementSearchCriteria protectionElementSearchCriteria;
		AuthorizationManager authorizationManager = ProvisionManager.getInstance().getAuthorizationManager();
		for (int i = 0; i < objectTypes.length; i++)
		{
			for (int j = 0; j < privilegeNames.length; j++)
			{
				try
				{
					protectionElement = new ProtectionElement();
					protectionElement.setObjectId(objectTypes[i] + "_*");
					protectionElementSearchCriteria=new ProtectionElementSearchCriteria(protectionElement);
					list = ProvisionManager.getInstance().getObjects(protectionElementSearchCriteria);
					privilegeMap=authorizationManager.getPrivilegeMap(user.getLoginName(),list);
					for (int k = 0; k < list.size(); k++)
					{
						protectionElement = (ProtectionElement) list.get(k);
					}

					objects.addAll(getObjectsForAssignPrivilege(privilegeMap, objectTypes[i],
							privilegeNames[j]));
				}
				catch (SMException smex)
				{
					logger.debug(" Exception in getting object of privileges", smex);
				}
			}
		}
		return objects;
			}
*/
	/**
	 * Checks whether an object type has any identified data associated with
	 * it or not.
	 * @param aliasName
	 * @return
	 */
	protected boolean hasAssociatedIdentifiedData(String aliasName)
	{
		boolean hasIdentifiedData = false;
		List identifiedData = new ArrayList();
		identifiedData = (List) AbstractClient.identifiedDataMap.get(aliasName);
		if (identifiedData != null)
		{
			hasIdentifiedData = true;
		}
		return hasIdentifiedData;
	}
	/**
	 * @param groups
	 * @param upManager
	 * @param role
	 * @return
	 * @throws CSObjectNotFoundException
	 */
	private Role getRole(Set groups, UserProvisioningManager upManager)
	throws CSObjectNotFoundException
	{
		Role role = null;
		Iterator<Group> iter = groups.iterator();
		if (iter.hasNext())
		{
			Group group = (Group) iter.next();
			if (group.getApplication().getApplicationName().equals(SecurityManagerPropertiesLocator.getInstance().getApplicationCtxName()))
			{
				RoleGroupDetailsBean sampleBean = new RoleGroupDetailsBean();
				sampleBean.setGroupName(group.getGroupName());
				RoleGroupDetailsBean requiredBean = getRequiredBean(sampleBean);
				String roleId = requiredBean.getRoleId();
				role = upManager.getRoleById(roleId);
			}
		}
		return role;
	}
	private RoleGroupDetailsBean getRequiredBean(RoleGroupDetailsBean sampleBean)
	{
		Map<RoleGroupDetailsBean, RoleGroupDetailsBean> map = RoleGroupLocator.getInstance().getRoleGroupDetailsMap();	
		return map.get(sampleBean);
	}
	/**
	 * 
	 * @param userGroupname
	 * @param userId
	 * @throws SMException
	 */
	private void checkForSufficientParamaters(String userGroupname,
			String userId) throws SMException {
		if (userId == null || userGroupname == null)
		{
			String mesg = "Null or insufficient Parameters passed";
			logger.debug(" Null or insufficient Parameters passed");
			ErrorKey defaultErrorKey = ErrorKey.getDefaultErrorKey();
			defaultErrorKey.setErrorMessage(mesg);
			throw new SMException(defaultErrorKey,null,null);	
		}
	}
	/**
	 * @param userGroupname
	 * @return
	 * @throws SMException
	 * @throws CSException
	 */
	private Group getUserGroup(String userGroupname) throws SMException, CSException
	{
		Group group = new Group();
		group.setGroupName(userGroupname);
		SearchCriteria searchCriteria = new GroupSearchCriteria(group);
		Group userGrp = null;
		List list = ProvisionManager.getInstance().getObjects(searchCriteria);
		if (!list.isEmpty())
		{
			userGrp = (Group) list.get(0);
		}

		return userGrp;
	}

}
