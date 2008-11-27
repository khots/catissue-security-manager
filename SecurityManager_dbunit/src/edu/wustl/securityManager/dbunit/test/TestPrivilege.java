
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
		Privilege priv = new Privilege("READ", 0);
		assertEquals(0, priv.getBitNumber());
		assertEquals("READ", priv.getPrivilegeName());
	}

	/**
	 * 
	 */
	public void testSetPrivDetails2()
	{
		Privilege priv = new Privilege("READ", 0);
		priv.setPrivilegeName(Constants.READ_DENIED);
		assertEquals(Constants.READ_DENIED, priv.getPrivilegeName());
	}

	/**
	 * 
	 */
	public void testSetPrivDetails()
	{
		Privilege priv = new Privilege("READ", 0);
		priv.setBitNumber(1);
		assertEquals(1, priv.getBitNumber());
	}
}
