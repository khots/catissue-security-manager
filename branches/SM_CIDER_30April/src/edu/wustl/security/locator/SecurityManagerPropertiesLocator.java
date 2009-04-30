
package edu.wustl.security.locator;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import edu.wustl.common.util.global.XMLParserUtility;
import edu.wustl.common.util.logger.Logger;
import edu.wustl.security.global.Constants;

/**
 * Reads the SecurityManager.properties file and loads properties to be referred by SecurityManager.
 * @author deepti_shelar
 */
public final class SecurityManagerPropertiesLocator
{
	/**
	 * Multiple CSM Setups
	 * Add a Map containing ctx name and class names.
	 */
	private Map<String, String> ctxNameClassNameMap=new HashMap<String, String>();
	
	/**
	 * Constant for context name node name
	 */
	private static final String APP_CTX_NAME="context-name";
	
	/**
	 * Constant for class name node name
	 */
	private static final String SM_CLASS_NAME="sm-class-name";
	
	/**
	 * Constant for application node name
	 */
	private static final String APPLICATION_NODE_NAME="application";
	
	/**
	 * Constant for default application
	 */
	private static final String DEFAULT_APPLICATION="default-application";
	
	/**
	 * Constant for default application name
	 */
	private static final String DEFAULT_APPLICATION_NAME="name";

	/**
	 * logger Logger - Generic logger.
	 */
	private static org.apache.log4j.Logger logger = Logger.getLogger(SecurityManagerPropertiesLocator.class);

	/**
	 * property names from SecurityManager.properties file .
	 */
	private String appCtxName;
	/**
	 * class name.
	 */
	private String className;

	/**
	 * Instantiating the class whenever loaded for the first time.
	 * The same instance will be returned whenever getInstance is called
	 */
	private static SecurityManagerPropertiesLocator singleObj = new SecurityManagerPropertiesLocator();

	/**
	 * Making the class singleton.
	 */
	private SecurityManagerPropertiesLocator()
	{
//		InputStream inputStream = SecurityManagerPropertiesLocator.class.getClassLoader()
//				.getResourceAsStream(Constants.SM_PROP_FILE);
		InputStream inputStream = SecurityManagerPropertiesLocator.class.getClassLoader().getResourceAsStream(Constants.SM_PROP_XML);
		//Properties smProp = new Properties();
		try
		{
			/**
			 * Multiple CSM Setups
			 * Populate the Map
			 */
//			smProp.load(inputStream);
//			inputStream.close();
//			appCtxName = smProp.getProperty(Constants.APP_CTX_NAME);
//			className = smProp.getProperty(Constants.SM_CLASSNAME);
			
			Document doc;
			
			doc = XMLParserUtility.getDocument(inputStream);
			
			//Populate the App Ctx Name Class Name Map
			NodeList appNodeLst = doc.getElementsByTagName(APPLICATION_NODE_NAME);
			populateMaps(appNodeLst);
			
			//Provide the default App Name
			NodeList defaultAppnodeList = doc.getElementsByTagName(DEFAULT_APPLICATION);
			if(defaultAppnodeList!=null && defaultAppnodeList.item(0)!=null)
			{
				Node defaultAppNode=defaultAppnodeList.item(0);
				if (defaultAppNode.getNodeType() == Node.ELEMENT_NODE)
				{
					Element defaultAppElmt = (Element) defaultAppNode;
					appCtxName=defaultAppElmt.getAttribute(DEFAULT_APPLICATION_NAME);
					className=ctxNameClassNameMap.get(appCtxName);
				}
			}
			
			
		}
		catch (IOException exception)
		{
			logger.fatal("Not able to initialize Security Manager Properties.", exception);
		} catch (ParserConfigurationException exception) {
			logger.fatal("Not able to initialize Security Manager Properties.", exception);
		} catch (SAXException exception) {
			logger.fatal("Not able to initialize Security Manager Properties.", exception);
		}
	}
	
	/**
	 * @param privNodeLst this method populate xml data to maps.
	 */
	private void populateMaps(final NodeList appNodeLst)
	{
		Node appNode;
		for (int s = 0; s < appNodeLst.getLength(); s++)
		{
			appNode = appNodeLst.item(s);
			if (appNode.getNodeType() == Node.ELEMENT_NODE)
			{
				addApplicationToMap(appNode);
			}
		}
	}

	/**
	 * @param privNode Node- xml privilege node
	 */
	private void addApplicationToMap(final Node appNode)
	{
		String appCtxName="";
		String smClassName="";
		Element appElmnt = (Element) appNode;
		appCtxName = (XMLParserUtility.getElementValue(appElmnt, APP_CTX_NAME)).trim();
		smClassName = (XMLParserUtility.getElementValue(appElmnt, SM_CLASS_NAME)).trim();
		ctxNameClassNameMap.put(appCtxName, smClassName);
	}

	/**
	 * Singleton class, will return the single object every time.
	 * @return SecurityManagerPropertiesLocator instance
	 */
	public static SecurityManagerPropertiesLocator getInstance()
	{
		return singleObj;
	}

	/**
	 * @return the appCtxName
	 */
	public String getApplicationCtxName()
	{
		return appCtxName;
	}

	/**
	 * @return the className
	 */
	public String getSecurityMgrClassName()
	{
		return className;
	}
	
	/**
	 * @return the className
	 */
	public String getSecurityMgrClassName(String appCtxcNameArg)
	{
		String smClassName=null;
		if(appCtxcNameArg!=null)
		{
			//appCtxName=appCtxcNameArg;
			smClassName=ctxNameClassNameMap.get(appCtxcNameArg);
			
		}
		return smClassName;
	}
}
