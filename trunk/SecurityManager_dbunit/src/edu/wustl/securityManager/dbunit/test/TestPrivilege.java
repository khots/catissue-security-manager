
package edu.wustl.securityManager.dbunit.test;

import edu.wustl.common.util.global.Constants;
import edu.wustl.security.privilege.Privilege;
import junit.framework.TestCase;

public class TestPrivilege extends TestCase
{

	/**
	 * 
	 */
	public void testGetPrivDetails()
	{
		Privilege priv = new Privilege("READ", 0, "READ");
		assertEquals(0, priv.getBitNumber());
		assertEquals("READ", priv.getPrivilegeName());
		assertEquals("READ", priv.getRoleName());
	}

	/**
	 * 
	 */
	public void testSetPrivDetails1()
	{
		Privilege priv = new Privilege("READ", 0, "READ");
		priv.setRoleName(Constants.READ_DENIED);
		assertEquals(Constants.READ_DENIED, priv.getRoleName());
	}

	/**
	 * 
	 */
	public void testSetPrivDetails2()
	{
		Privilege priv = new Privilege("READ", 0, "READ");
		priv.setPrivilegeName(Constants.READ_DENIED);
		assertEquals(Constants.READ_DENIED, priv.getPrivilegeName());
	}

	/**
	 * 
	 */
	public void testSetPrivDetails()
	{
		Privilege priv = new Privilege("READ", 0, "READ");
		priv.setBitNumber(1);
		assertEquals(1, priv.getBitNumber());
	}
}
