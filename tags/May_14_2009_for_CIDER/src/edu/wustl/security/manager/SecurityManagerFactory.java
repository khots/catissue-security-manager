
package edu.wustl.security.manager;

import java.util.HashMap;
import java.util.Map;

import edu.wustl.security.exception.SMException;
import edu.wustl.security.global.ProvisionManager;
import edu.wustl.security.global.Utility;
import edu.wustl.security.locator.SecurityManagerPropertiesLocator;

/**
 * Factory to create an instance of ISecurityManager.
 * @author deepti_shelar
 *
 */
public class SecurityManagerFactory
{
	/**
	 * Multiple CSM Setups
	 * Add an overloaded method accepting the ctx name and returning the required SecurityManager instantce.
	 */
	
	/**
	 * Static variable to store all the SM Instances and return the required instance when
	 * getSecurityManager() method is called.
	 */
	public static Map<String, ISecurityManager> securityManagersMap=new HashMap<String, ISecurityManager>();
	
	/**
	 * Returns the instance of SM.
	 * @return ISecurityManager sm instance
	 * @throws SMException smexc
	 */
	public static ISecurityManager getSecurityManager() throws SMException
	{
		String appCtxName=SecurityManagerPropertiesLocator.getInstance().getApplicationCtxName();
		String smClassName = SecurityManagerPropertiesLocator.getInstance().getSecurityMgrClassName();
		ISecurityManager securityManager = null;
		if (smClassName == null)
		{
			Utility.getInstance().throwSMException(null, "Could not get the className ", "sm.operation.error");
		}
		else
		{
			securityManager = getSMInstance(smClassName);
			securityManager.setAppCtxName(appCtxName);
			securityManager.setProvisionManager(new ProvisionManager(appCtxName));
		}
		return securityManager;
	}
	
	/**
	 * Returns the instance of SM.
	 * @return ISecurityManager sm instance
	 * @throws SMException smexc
	 */
	public static ISecurityManager getSecurityManager(String appCtxName) throws SMException
	{
		String smClassName = SecurityManagerPropertiesLocator.getInstance().getSecurityMgrClassName(appCtxName);
		ISecurityManager securityManager = null;
		if (smClassName == null)
		{
			Utility.getInstance().throwSMException(null, "Could not get the className ", "sm.operation.error");
		}
		else
		{
			securityManager = getSMInstance(smClassName);
			securityManager.setAppCtxName(appCtxName);
			securityManager.setProvisionManager(new ProvisionManager(appCtxName));
		}
		return securityManager;
	}

	/**
	 * @param smClassName class name for SM.
	 * @throws SMException exc
	 * @return ISecurityManager sm instance
	 */
	private static ISecurityManager getSMInstance(String smClassName) throws SMException
	{
		ISecurityManager securityManager = null;
		try
		{
			Class className = Class.forName(smClassName);
			securityManager = (ISecurityManager) className.newInstance();
		}
		catch (ClassNotFoundException e)
		{
			String message = "Expected SecurityManager class name is not provided in properties file";
			Utility.getInstance().throwSMException(e, message, "sm.operation.error");
		}
		catch (InstantiationException e)
		{
			String message = "Can not instantiate class ";
			Utility.getInstance().throwSMException(e, message, "sm.operation.error");
		}
		catch (IllegalAccessException e)
		{
			String message = "Illegal access to the class ";
			Utility.getInstance().throwSMException(e, message, "sm.operation.error");
		}
		return securityManager;
	}
}
