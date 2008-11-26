/**
 * PrivilegeCacheManager will manage all the instances of PrivilegeCache. 
 * This will be a singleton. 
 * Instances of PrivilegeCache can be accessed from the instance of PrivilegeCacheManager
 */

package edu.wustl.security.privilege;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.exception.SMException;
import edu.wustl.security.global.Utility;
import gov.nih.nci.security.UserProvisioningManager;
import gov.nih.nci.security.authorization.ObjectPrivilegeMap;
import gov.nih.nci.security.authorization.domainobjects.Group;
import gov.nih.nci.security.authorization.domainobjects.ProtectionElement;
import gov.nih.nci.security.authorization.domainobjects.User;
import gov.nih.nci.security.exceptions.CSException;
import gov.nih.nci.security.exceptions.CSObjectNotFoundException;

/**
 * @author ravindra_jain
 * creation date : 14th April, 2008
 * @version 1.0
 */
public final class PrivilegeManager
{

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(PrivilegeManager.class);

	/* Singleton instance of PrivilegeCacheManager
	 */
	private static PrivilegeManager instance = new PrivilegeManager();

	/* the map of login name and corresponding PrivilegeCache  
	 */
	private Map<String, PrivilegeCache> privilegeCaches;

	private PrivilegeUtility privilegeUtility;

	private List<String> lazyObjects;
	private List<String> classes;
	private List<String> eagerObjects;

	/**
	 * private constructor to make the class singleton
	 */
	private PrivilegeManager()
	{
		lazyObjects = new ArrayList<String>();
		classes = new ArrayList<String>();
		eagerObjects = new ArrayList<String>();
		privilegeUtility = new PrivilegeUtility();
		privilegeCaches = new HashMap<String, PrivilegeCache>();
		try
		{
			readXmlFile("CacheableObjects.xml");
		}
		catch (SMException e)
		{
			logger.debug(e.getStackTrace());
		}
	}

	/**
	 * return the Singleton PrivilegeCacheManager instance.
	 */
	public static PrivilegeManager getInstance()
	{
		return instance;
	}

	/**
	 * to return the PrivilegeCache object from the Map of PrivilegeCaches
	 * @param loginName
	 * @return
	 * @throws Exception
	 */
	public PrivilegeCache getPrivilegeCache(String loginName)
	{
		PrivilegeCache privilegeCache = privilegeCaches.get(loginName);
		if (privilegeCache == null)
		{
			privilegeCache = new PrivilegeCache(loginName);
			privilegeCaches.put(loginName, privilegeCache);
		}

		return privilegeCache;
	}

	/**
	 * To get all PrivilegeCache objects.
	 * 
	 * @return
	 * @throws Exception
	 */
	public Collection<PrivilegeCache> getPrivilegeCaches()
	{
		return privilegeCaches.values();
	}

	/**
	 * This method will generally be called from CatissueCoreSesssionListener.sessionDestroyed 
	 * in order to remove the corresponding PrivilegeCache from the Session.
	 * @param userId
	 */
	public void removePrivilegeCache(String userId)
	{
		privilegeCaches.remove(userId);
	}

	/**
	 * This Utility method is called dynamically as soon as a 
	 * Site or CollectionProtocol object gets created through the UI
	 * & adds detials regarding that object to the PrivilegeCaches of
	 * appropriate users in Session.
	 *
	 * @param objectId
	 * @throws SMException 
	 */
	private void addObjectToPrivilegeCaches(String objectId) throws SMException
	{
		try
		{
			Collection<PrivilegeCache> listOfPrivCaches = getPrivilegeCaches();

			ProtectionElement protectionElement = privilegeUtility.getUserProvisioningManager()
					.getProtectionElement(objectId);

			Collection<ProtectionElement> protElements = new ArrayList<ProtectionElement>();
			protElements.add(protectionElement);

			for (PrivilegeCache privilegeCache : listOfPrivCaches)
			{
				Collection<ObjectPrivilegeMap> objPrivMapCol = privilegeUtility
						.getUserProvisioningManager().getPrivilegeMap(
								privilegeCache.getLoginName(), protElements);

				if (!objPrivMapCol.isEmpty())
				{
					privilegeCache.addObject(objectId, objPrivMapCol.iterator().next()
							.getPrivileges());
				}
			}
		}
		catch (CSObjectNotFoundException e)
		{
			Utility.getInstance().throwSMException(e, e.getMessage());
		}
		catch (CSException e)
		{
			Utility.getInstance().throwSMException(e, e.getMessage());
		}
	}

	/**
	 * 
	 * @param authorizationData data
	 * @param protectionObjects protObjs
	 * @param dynamicGroups set
	 * @param objectId id
	 * @throws SMException 
	 */
	public void insertAuthorizationData(List authorizationData, Set protectionObjects,
			String[] dynamicGroups, String objectId) throws SMException
	{
		PrivilegeUtility utility = new PrivilegeUtility();
		try
		{
			utility.insertAuthorizationData(authorizationData, protectionObjects, dynamicGroups);
		}
		catch (SMException exception)
		{
			String mess = "Exception in insertAuthorizationData:" + exception;
			Utility.getInstance().throwSMException(exception, mess);
		}

		addObjectToPrivilegeCaches(objectId);
	}

	/**
	 * 
	 * @param fileName name of the file
	 * @throws SMException 
	 */
	private void readXmlFile(String fileName) throws SMException
	{
		try
		{
			Document doc = createDoc(fileName);
			if (doc != null)
			{
				Element root = doc.getDocumentElement();
				getClasses(root);
				getObjects(root);
			}
		}
		catch (ParserConfigurationException excp)
		{
			String mess = "DocumentBuilder cannot be created:";
			Utility.getInstance().throwSMException(excp, mess);
		}
		catch (SAXException excp)
		{
			String mess = "Not able to parse xml file:" + fileName;
			Utility.getInstance().throwSMException(excp, mess);
		}
		catch (IOException excp)
		{
			String mess = "Not able to parse xml file: IOException" + fileName;
			Utility.getInstance().throwSMException(excp, mess);
		}

	}

	/**
	 * @param root
	 */
	private void getObjects(Element root)
	{
		NodeList nodeList1 = root.getElementsByTagName("ObjectType");

		int length1 = nodeList1.getLength();

		for (int counter = 0; counter < length1; counter++)
		{
			Element element = (Element) (nodeList1.item(counter));
			String temp = element.getAttribute("pattern");
			String lazily = element.getAttribute("cacheLazily");

			if (lazily.equalsIgnoreCase("false") || lazily.equalsIgnoreCase(""))
			{
				eagerObjects.add(temp);
			}
			else
			{
				lazyObjects.add(temp.replace('*', '_'));
			}
		}
	}

	/**
	 * @param root
	 */
	private void getClasses(Element root)
	{
		NodeList nodeList = root.getElementsByTagName("Class");

		int length = nodeList.getLength();

		for (int counter = 0; counter < length; counter++)
		{
			Element element = (Element) (nodeList.item(counter));
			String temp = element.getAttribute("name");
			classes.add(temp);
		}
	}

	/**
	 * @param fileName
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 * @throws IOException
	 */
	private Document createDoc(String fileName) throws ParserConfigurationException, SAXException,
			IOException
	{
		String xmlFileName = fileName;
		Document doc = null;
		InputStream inputXmlFile = this.getClass().getClassLoader()
				.getResourceAsStream(xmlFileName);

		if (inputXmlFile == null)
		{
			logger.debug("FileNotFound with name : " + fileName);
		}
		else
		{
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			doc = builder.parse(inputXmlFile);
		}
		return doc;
	}

	public List<String> getClasses()
	{
		return Collections.unmodifiableList(classes);
	}

	public List<String> getLazyObjects()
	{
		return Collections.unmodifiableList(lazyObjects);
	}

	public List<String> getEagerObjects()
	{
		return Collections.unmodifiableList(eagerObjects);
	}

	/**
	 * get a set of login names of users having given privilege on given object
	 *
	 * @param objectId
	 * @param privilege
	 * @return
	 * @throws CSException
	 */
	public Set<String> getAccesibleUsers(String objectId, String privilege) throws SMException
	{
		Set<String> result = new HashSet<String>();
		try
		{
			UserProvisioningManager userProvManager = privilegeUtility.getUserProvisioningManager();

			List<Group> list = userProvManager.getAccessibleGroups(objectId, privilege);
			for (Group group : list)
			{
				Set<User> users = group.getUsers();
				for (User user : users)
				{
					result.add(user.getLoginName());
				}
			}
		}
		catch (CSException excp)
		{
			String mess = "Not able to get instance of UserProvisioningManager:";
			Utility.getInstance().throwSMException(excp, mess);
		}
		return result;
	}

}
