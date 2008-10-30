/*
 * Created on Oct 4, 2005
 *
 * TODO To change the template for this generated file go to
 * Window - Preferences - Java - Code Style - Code Templates
 */

package edu.wustl.security.impl;

import org.hibernate.SessionFactory;

import edu.wustl.security.locator.SecurityManagerPropertiesLocator;
import edu.wustl.security.manager.SecurityManager;
import gov.nih.nci.security.system.ApplicationSessionFactory;

/**
 * @author aarti_sharma
 *
 * TODO To change the template for this generated type comment go to
 * Window - Preferences - Java - Code Style - Code Templates
 */
public class UserProvisioningManagerImpl
		extends
			gov.nih.nci.security.provisioning.UserProvisioningManagerImpl
{

	/**
	 * @param arg0
	 * @throws Exception
	 */
	public UserProvisioningManagerImpl(String arg0) throws Exception
	{
		super(arg0);

	}

	/**
	 * @param arg0
	 * @throws Exception
	 */
	public UserProvisioningManagerImpl() throws Exception
	{
		/** Modified by amit_doshi
		 *  code reviewer abhijit_naik 
		 */
		super(SecurityManagerPropertiesLocator.APPLICATION_CONTEXT_NAME);
		SessionFactory sf = ApplicationSessionFactory
				.getSessionFactory(SecurityManagerPropertiesLocator.APPLICATION_CONTEXT_NAME);
		super.setAuthorizationDAO(new AuthorizationDAOImpl(sf,
				SecurityManagerPropertiesLocator.APPLICATION_CONTEXT_NAME));
	}

}
