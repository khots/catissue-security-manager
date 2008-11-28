
package edu.wustl.securityManager.dbunit.test;

import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;
import edu.wustl.common.util.global.Constants;
import edu.wustl.security.global.Utility;
import edu.wustl.security.privilege.PrivilegeType;
/**
 * Test case for Utility class.
 * @author deepti_shelar
 *
 */
public class TestUtility extends TestCase
{
	/**
	 * getPrivilegeType for obj.
	 */
	public void testGetPrivilegeTypeObj()
	{
		Map<String, String> tagKeyValueMap = new HashMap<String, String>();
		tagKeyValueMap.put(Constants.PRIVILEGE_TAG_NAME, "2");
		PrivilegeType pType = Utility.getInstance().getPrivilegeType(tagKeyValueMap);
		assertEquals(PrivilegeType.ObjectLevel, pType);
	}
	/**
	 * getPrivilegeType for class.
	 */
	public void testGetPrivilegeTypeClass()
	{
		Map<String, String> tagKeyValueMap = new HashMap<String, String>();
		tagKeyValueMap.put(Constants.PRIVILEGE_TAG_NAME, "1");
		PrivilegeType pType = Utility.getInstance().getPrivilegeType(tagKeyValueMap);
		assertEquals(PrivilegeType.ClassLevel, pType);
	}
	/**
	 * getPrivilegeType for insecure.
	 */
	public void testGetPrivilegeTypeInsecure()
	{
		Map<String, String> tagKeyValueMap = new HashMap<String, String>();
		tagKeyValueMap.put(Constants.PRIVILEGE_TAG_NAME, "0");
		PrivilegeType pType = Utility.getInstance().getPrivilegeType(tagKeyValueMap);
		assertEquals(PrivilegeType.InsecureLevel, pType);
	}
	/**
	 * getIsBirthDate for true.
	 */
	public void testIsBirthDateTrue()
	{
		Map<String, String> tagKeyValueMap = new HashMap<String, String>();
		tagKeyValueMap.put(edu.wustl.security.global.Constants.BDATE_TAG_NAME, Constants.TRUE);
		boolean isBirthDate = Utility.getInstance().getIsBirthDate(tagKeyValueMap);
		assertTrue(isBirthDate);
	}
	/**
	 * getIsBirthDate for false.
	 */
	public void testIsBirthDateFalse()
	{
		Map<String, String> tagKeyValueMap = new HashMap<String, String>();
		tagKeyValueMap.put(edu.wustl.security.global.Constants.BDATE_TAG_NAME, Constants.FALSE);
		boolean isBirthDate = Utility.getInstance().getIsBirthDate(tagKeyValueMap);
		assertFalse(isBirthDate);
	}
}
