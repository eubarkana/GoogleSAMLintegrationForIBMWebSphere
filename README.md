# Google SAML SSO integration For IBM WebSphere Application Server
This document describes and highlights the key points of Google SAML configuration on IBM WebSphere Application Server. Integration code is also included written in JAVA.

## Requirements

Required products and the configuration names within the scenario are given below:

1- IBM WebSphere Application Server v8.5.5.x(8.5.5.16 is documented in the scenario) has to be installed.
  - Queue manager (CAUDAQM) and server connection channels (non ssl: TO.CAUDA channel) need to be created
  - At least one queue (TESTQ) needs to be created.

2- Google G-Suite needs to be in place.

3- Eclipse development tool needs to be installed. (Needed for creating the Java integration code)

