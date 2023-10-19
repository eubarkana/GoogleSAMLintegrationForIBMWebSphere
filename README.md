# Google SAML SSO integration For IBM WebSphere Application Server
This document describes and highlights the key points of Google SAML configuration on IBM WebSphere Application Server. Integration code is also included written in JAVA.




# IBMSAMLSSO
SAML SSO integration between IBM WebSphere & Google G-Suite

## Table of contents

- [IBMSAMLSSO](#ibmsamlsso)
  - [Table of contents](#table-of-contents)
  - [Prerequisites](#prerequisites)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
  - [Enable SAML on WebSphere](#enable-saml-on-websphere)
  - [Configure SSO Partners for Identity Provider Initiated SSO](#configure-sso-partners-for-identity-provider-initiated-sso)
  - [Configure Additional Properties](#configure-additional-properties)
  - [Configure SAML Provider Class](#configure-saml-provider-class)
  - [Configure LDAP properties on WebSphere Application Server](#configure-ldap-properties-on-websphere-application-server)
  - [Configure Google G-Suite Properties](#configure-google-g-suite-properties)


## Prerequisites

This document describes how to configure Google SAML with IBM BPM WebSphere
Application Server.
The environment used in this document is as follows:
OS : ```Linux (Ubuntu x86_64)```
Installed products on OS:
```
Product List
--------------------------------------------------------------------------------
BPMPC installed
ND installed
Installed Product
--------------------------------------------------------------------------------
Name IBM Business Automation Workflow Enterprise
Version 8.6.1.19003
ID BPMPC
Build Level 20191209-051043
Build Date 12/9/19
Package com.ibm.bpm.ADV.v85_8.6.10019003.20191209_0812
Architecture x86-64 (64 bit)
Installed Features IBM Business Automation Workflow Enterprise Production License
Installed Product
--------------------------------------------------------------------------------
Name IBM WebSphere Application Server Network Deployment
Version 8.5.5.16
ID ND
Build Level cf161930.02
Build Date 8/1/19
Package com.ibm.websphere.ND.v85_8.5.5016.20190801_0951
Java SE Version 8
Architecture x86-64 (64 bit)
Installed Features IBM 64-bit WebSphere SDK for Java
WebSphere Application Server Full Profile
EJBDeploy tool for pre-EJB 3.0 modules
Embeddable EJB container
Stand-alone thin clients and resource adapters
```

<img width="707" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/95eef8c4-7573-4bb4-8915-8a620ac4f38d">

## Requirements

Required products and the configuration names within the scenario are given below:

1- IBM WebSphere Application Server v8.5.5.x has to be installed.

2- Google G-Suite needs to be in place.

3- Eclipse development tool needs to be installed. (Needed for creating the Java integration code)

## Introduction

This tutorial will get you started with using SAML integration between WebSphere Application Server and Google G-Suite.

SAML stands for **Security Assertion Markup Language**. It is an XML-based open-standard for transferring identity data between two parties: an identity provider (IdP) and a service provider (SP).

*  **Identity Provider** — Performs authentication and passes the user's identity and authorization level to the service provider.

*  **Service Provider** — Trusts the identity provider and authorizes the given user to access the requested resource.

WebSphere supports IdP-initiated SAML SSO integration.

After enabling the SAML Web SSO feature, you must configure WebSphere Application Server as a service provider (SP) partner to participate in the IdP-initiated single sign-on scenarios with other identity providers.

In this document, we will set up SAML configuration between Google G-Suite and WebSphere Application Server:


## Enable SAML on WebSphere

This document shows how to define the channel through MQ explorer(GUI based). You can also define the channel with runmqsc commands.

1. Using the administrative console, install the *app_server_root/installableApps/WebSphereSamlSP.ear* file to your application server or cluster. To install this application choose one of the options:
   - Use WebSphere administrative console
   - Under app_server_root/bin run the
    ```
    wsadmin -f installSamlACS.py install <nodeName> <serverName>
    ```
    or
    ```
    wsadmin -f installSamlACS.py install <clusterName>
    ```
2. Enable Trust association:
   - From WebSphere administrative console, navigate to **Security->Global security->Web and SIP security->Trust association**

   - Click check box for “*Enable trust association*”


<img width="557" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/6673f614-69dd-4c9d-a959-e4a497cd693c">


3. Enter the interceptors
   - From WebSphere administrative console, navigate to **Security->Global security->Web and SIP security->Trust association->Interceptors**
   - Click *new*
     Interceptor class name:
        `com.ibm.ws.security.web.saml.ACSTrustAssociationInterceptor`
   - After creating the class name, click on the newly created class and add custom properties for `sso_1.sp.acsURL` and `sso_1.sp.idMap` as shown below:


<img width="722" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/adc2a0ef-5c01-4b4c-aa6b-f622d88c4d58">


Custom properties:
| Name | Value | Sample |
| ---- | ----- | ------ |
| `sso_1.sp.acsUrl` | `https://<hostname>:<sslport>/samlsps/<anyURI pattern string>` | `https://<server>/<context_root>/samlSSO` |
| `sso_1.sp.idMap`  | `localRealm` |  |

4. Under **Global security->Custom Properties** click *new*. Enter the values below:

| Name | Value |
| ---- | ----- |
| `com.ibm.websphere.security.DeferTAItoSSO` | `com.ibm.ws.security.web.saml.ACSTrustAssociationInterceptor` |


The property `com.ibm.websphere.security.DeferTAItoSSO`, was previously used in the default configuration (set to `com.ibm.ws.security.spnego.TrustAssociationInterceptorImpl`) of all installed servers. Now it is only used as part of the SAML configuration. Therefore, even if this property already exists in your system configuration, you must change its value to `com.ibm.ws.security.web.saml.ACSTrustAssociationInterceptor`. Multiple values, separated with commas, cannot be specified for this property. It must be set to a single SAML TAI.


5. Under **Global security->Custom Properties** click *new*. Enter the values below:

| **Name** | **Value** |
| ---- | ----- |
| `com.ibm.websphere.security.InvokeTAIbeforeSSO` | `com.ibm.ws.security.web.saml.ACSTrustAssociationInterceptor` |



## Configure SSO Partners for Identity Provider Initiated SSO

1. Start the WebSphere Application Server deployment manager using command below:
    `app_server_root/profiles/DmgrProfile/bin/starManager.sh`
2. Place IdP provided *“FederationMetadata.xml”* file under
    `app_server_root/profiles/DmgrProfile` folder. Then, make sure that WAS is up and running and run the following commands.

```
cd /opt/IBM/WebSphere/AppServer/bin
./wsadmin.sh -lang jython -username wasadmin -password xxxxxxx
AdminTask.importSAMLIdpMetadata('-idpMetadataFileName GoogleIDPMetadata.com.xml -idpId 1 -ssoId 1 -signingCertAlias googleidpcert')
AdminConfig.save()
quit
```

Check WebSphere Admin console to verify the certificate is imported to *CellDefaultTrustStore*

<img width="452" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/9ef5c095-c9a2-486a-932c-07f02aeef148">

Restart Websphere application server.

Check the properties for TAI to see two more entries are in place:

<img width="663" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/f78cdce2-70d1-4dd0-8048-278444d00794">

3. Add IdP realms to the list of inbound trusted realms. For each Identity provider that is used with your WebSphere Application Server service provider, you must grant inbound trust to all the realms that are used by the identity provider.
You can grant inbound trust to the identity providers using either the administrative console or the `wsadmin` command utility.

* Add inbound trust using the administrative console.
  - Click **Global security**.
  - Under user account repository, click **Configure**.
  - Click **Trusted authentication realms - inbound**.
  - Click **Add External Realm**.

Fill in the external realm name as entity ID:

<img width="712" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/ed0ad594-c18b-47b1-938a-571d14814f13">

   - Click **OK** and **Save** changes to the master configuration.


## Configure Additional Properties

Login to WAS Admin Console and navigate to *Security -> Web and SIP security-> Trust association* and click **Interceptors** link and move to **ACSTrustAssociationInterceptor** details

<img width="684" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/5c81a0ab-0970-44be-8902-57b2baf7edc0">

Click **New** to add the Custom properties below:
*  **sso_1.sp.EntityID** = *(Link of the client to reach)*
*  **sso_1.sp.targetUrl** = *(Link of the client to reach as in EntityID of sp)*
*  **sso_1.idp_1.certAlias** = `googleidpcert` *(Imported certificate alias)*
*  **sso_1.sp.login.error.page** = `com.ibm.baw.auth.saml.SAMLProvider` *(Custom SAML provider class discussed in the next section)*
*  **sso_1.sp.trustedAlias** = `googleidpcert` *(Imported certificate alias)*
*  **sso_1.sp.useRealm** = `defaultWIMFileBasedRealm` *(Realm name of your Federated repository)*


Custom properties definitions can be found from this link:
https://www.ibm.com/support/knowledgecenter/SSAW57_8.5.5/com.ibm.websphere.nd.multiplatform.doc/ae/rwbs_samltaiproperties.html



## Configure SAML Provider class

In case of any exception of first GET action, which is generated and directed by WebSphere to Google IDP SAML Service our small custom java class will be called by WebSphere. This class will prepare manually SAML Auth Request XML with all required parameters related with registered client information.
In our case we give name “*SAMLProvider*” to this custom class. its signature is like

```
public class SAMLProvider implements AuthnRequestProvider{…
```

Class should be registered with package name under ACS interceptor with *sso_{idp number}.sp.login.error.page* saml key name. It should be look below:

<img width="687" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/d97a8c25-6a6a-4e68-9684-d1b00cdf1192">


Main method called by WebSphere and responsible with SAML IDP call is `getAuthnRequest` named method and

```
public HashMap<String, String> getAuthnRequest(HttpServletRequest req, String errorMsg, String acsUrl,ArrayList<String> ssoUrls) throws NotImplementedException {
    Tr.debug(tc, "Client SAML-SAMLProvider.getAuthnRequest() begin");
    HashMap<String, String> map = new HashMap<String, String>();
    String ssoUrl = "https://accounts.google.com/o/saml2/idp?idpid=xyz";
    map.put(AuthnRequestProvider.SSO_URL, ssoUrl);
    String relayState = "https://workflow.aaa.com/ProcessPortal";
    map.put(AuthnRequestProvider.RELAY_STATE, relayState);
    String requestId = generateRandom(10);
    map.put(AuthnRequestProvider.REQUEST_ID, requestId);
    String authnMessage = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        +"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" " + "ID=\"" + requestId +"\" "
        + "IssueInstant=\"" + UTC.format(new java.util.Date()) +"\" "
        + "ForceAuthn=\"false\" IsPassive=\"false\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "
        + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" "
        + "AssertionConsumerServiceURL=\"" + acs + "\" " + "Destination=\"" + destination + "\"> "
        + "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + issuer +"</saml:Issuer>"
        + "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress\" "
        + "AllowCreate=\"true\" /> <samlp:RequestedAuthnContext Comparison=\"exact\"> "
        + "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
        + "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
        + "</samlp:RequestedAuthnContext></samlp:AuthnRequest>";
    Tr.debug(tc, "Client SAML-Auth Request:"+authnMessage);
    try {
        String encodedAuthRequest=getEncodedAuthnRequest(false,authnMessage);
        map.put(AuthnRequestProvider.AUTHN_REQUEST, encodedAuthRequest);
        Tr.debug(tc, "Client SAML-encoded Auth Request:"+encodedAuthRequest);
    } catch (Exception e) {
        e.printStackTrace();
    }
    Tr.debug(tc, "Client SAML-SAMLProvider.getAuthnRequest() end");
    return map;
}
```

And other used utility methods and parameters to create ultimate SAML POST Request are like below

```
private String acs="https://workflow.aaa.com/samlsps";
private String destination="https://accounts.google.com/o/saml2/idp?idpid=xyz";
private String issuer="https://workflow.aaa.com/ProcessPortal";
private static final String CLIENT_PREFIX="TY_";
private static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
private static final String CHAR_UPPER = CHAR_LOWER.toUpperCase();
private static final String NUMBER = "0123456789";
private static final String DATA_FOR_RANDOM_STRING = CHAR_LOWER + CHAR_UPPER + NUMBER;
private static SecureRandom random = new SecureRandom();

private String generateRandom(int length) {
    if (length < 1) throw new IllegalArgumentException();
    StringBuilder sb = new StringBuilder(length);
    for (int i = 0; i < length; i++) {
        int rndCharAt = random.nextInt(DATA_FOR_RANDOM_STRING.length());
        char rndChar = DATA_FOR_RANDOM_STRING.charAt(rndCharAt);
        sb.append(rndChar);
    }
    return CLIENT_PREFIX+sb.toString();
}

private String getEncodedAuthnRequest(Boolean deflated,String authnMessage) throws IOException {
    Tr.debug(tc, "Client SAML-getEncodedAuthnRequest() begin. Parameter deflated:"+deflated);
    String encodedAuthnRequest;
    if (deflated) {
        encodedAuthnRequest = Util.deflatedBase64encoded(authnMessage);
    } else {
        encodedAuthnRequest = Util.base64encoder(authnMessage);
    }
    Tr.debug(tc, "Client SAML-getEncodedAuthnRequest() end");
    return encodedAuthnRequest;
}
```

## Configure LDAP properties on WebSphere Application Server

Users trying to use SAML with Google will use email address to authenticate from Service Provider. In order to authenticate users from LDAP, email has to be used as login properties from WebSphere Application Server.

Once repository is added to WebSphere Application Server, the default behavior of the login properties used is **uid**. In order to change this behavior, go to **Global security->Configure**

<img width="351" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/d6a61788-050f-4460-8e8a-612eb89f9e07">

Click on the repository identifier you have defined.

Then change the “**Federated repository properties for login**” to *mail*:

<img width="293" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/aab1db1a-8f64-4ef2-ac26-6a91e5173c42">

**Apply** and **Save** changes. Restart deployment manager, nodeagent and servers.

## Configure Google G-suite properties

Google side should have the following properties set:

<img width="441" alt="image" src="https://github.com/eubarkana/GoogleSAMLintegrationForIBMWebSphere/assets/52744532/46172a09-ffa0-4b71-9bf9-17267a262fc6">


