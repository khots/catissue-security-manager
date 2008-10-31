package edu.wustl.security.global;

import java.util.List;

import edu.wustl.common.security.exceptions.SMException;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
import edu.wustl.security.manager.SecurityManager;
import gov.nih.nci.security.AuthenticationManager;
import gov.nih.nci.security.AuthorizationManager;
import gov.nih.nci.security.SecurityServiceProvider;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.domainobjects.Group;
import gov.nih.nci.security.authorization.domainobjects.Role;
import gov.nih.nci.security.dao.GroupSearchCriteria;
import gov.nih.nci.security.dao.RoleSearchCriteria;
import gov.nih.nci.security.dao.SearchCriteria;
import gov.nih.nci.security.exceptions.CSException;
/**
 * Class to provide required objects from csm apis.
 * @author deepti_shelar
 *
 */
public class ProvisionManager 
{
	/**
	 * logger Logger - Generic logger.
	 */
	protected static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManager.class);

	private static AuthenticationManager authenticationManager = null;

	private static AuthorizationManager authorizationManager = null;
	/**
	 * Returns the UserProvisioningManager singleton object.
	 *
	 * @return
	 * @throws	CSException
	 */
	public static final UserProvisioningManager getUserProvisioningManager() throws CSException
	{
		return (UserProvisioningManager) getAuthorizationManager();
	}
	/**
	 * Returns the AuthenticationManager for the caTISSUE Core. This method
	 * follows the singleton pattern so that only one AuthenticationManager is
	 * created for the caTISSUE Core.
	 *
	 * @return
	 * @throws	CSException
	 */
	public static final AuthenticationManager getAuthenticationManager() throws CSException
	{
		if (authenticationManager == null)
		{
			authenticationManager = SecurityServiceProvider
					.getAuthenticationManager(SecurityManagerPropertiesLocator.APPLICATION_CONTEXT_NAME);
		}
		return authenticationManager;
	}

	/**
	 * Returns the Authorization Manager for the caTISSUE Core. This method
	 * follows the singleton pattern so that only one AuthorizationManager is
	 * created.
	 *
	 * @return
	 * @throws	CSException
	 */
	public static final AuthorizationManager getAuthorizationManager() throws CSException
	{

		if (authorizationManager == null)
		{
			authorizationManager = SecurityServiceProvider
					.getAuthorizationManager(SecurityManagerPropertiesLocator.APPLICATION_CONTEXT_NAME);
		}

		return authorizationManager;
	}
	/**
	* Returns group id from Group name
	* @param groupName
	* @return
	* @throws CSException 
	* @throws SMException 
	*/
	public static final String getGroupID(String groupName) throws CSException, SMException
	{
		List list;
		String groupId=null;
		Group group = new Group();
		group.setGroupName(groupName);
		UserProvisioningManager userProvisioningManager=getUserProvisioningManager();
		SearchCriteria searchCriteria = new GroupSearchCriteria(group);
		group.setApplication(userProvisioningManager.getApplication(SecurityManagerPropertiesLocator.APPLICATION_CONTEXT_NAME));
		list = getObjects(searchCriteria);
		if (!list.isEmpty())
		{
			group = (Group) list.get(0);
			groupId= group.getGroupId().toString();
		}

		return groupId;
	}

	/**
	 * Returns role id from role name
	 * @param roleName
	 * @return
	 */
	public static final String getRoleID(String roleName) throws CSException, SMException
	{
		String roleId=null;
		Role role = new Role();
		role.setName(roleName);
		SearchCriteria searchCriteria = new RoleSearchCriteria(role);
		UserProvisioningManager userProvisioningManager= getUserProvisioningManager();
		role.setApplication(userProvisioningManager.getApplication(SecurityManagerPropertiesLocator.APPLICATION_CONTEXT_NAME));
		List list = getObjects(searchCriteria);
		if (!list.isEmpty())
		{
			role = (Role) list.get(0);
			roleId=role.getId().toString();
		}
		return roleId;
	}
	/**
	 * Returns list of objects corresponding to the searchCriteria passed.
	 * @param searchCriteria
	 * @return List of resultant objects
	 * @throws SMException if searchCriteria passed is null or if search results in no results
	 * @throws CSException
	 */
	public static final List getObjects(SearchCriteria searchCriteria) throws SMException, CSException
	{
		if (null == searchCriteria)
		{
			logger.debug("searchCriteria is null");
			throw new SMException("Null Parameters passed");
		}
		UserProvisioningManager userProvisioningManager = getUserProvisioningManager();
		List list = userProvisioningManager.getObjects(searchCriteria);
		if (null == list || list.size() <= 0)
		{
			logger.warn("Search resulted in no results");
		}
		return list;
	}
}
