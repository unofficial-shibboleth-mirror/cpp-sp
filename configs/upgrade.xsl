<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:oldconf="urn:mace:shibboleth:target:config:1.0"
    xmlns:cred="urn:mace:shibboleth:credentials:1.0"
    xmlns:conf="urn:mace:shibboleth:2.0:native:sp:config"
    xmlns="urn:mace:shibboleth:2.0:native:sp:config"
    exclude-result-prefixes="oldconf cred">

    <xsl:param name="idp"/>
    
    <!--Force UTF-8 encoding for the output.-->
    <xsl:output omit-xml-declaration="no" method="xml" encoding="UTF-8"/>

    <xsl:variable name="spaces" select="string('                                                                                          ')"/>

    <xsl:template match="/">
        <xsl:apply-templates/>
    </xsl:template>
    
    <xsl:template match="oldconf:SPConfig">
        <xsl:text>&#10;</xsl:text>
        <SPConfig logger="{@logger}" clockSkew="{@clockSkew}">
            <xsl:text>&#10;</xsl:text>
            <xsl:comment>
                <xsl:text> Generated by upgrade utility: check carefully before deploying. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;&#10;</xsl:text>
            <xsl:apply-templates select="oldconf:Global"/>
            <xsl:text>&#10;</xsl:text>
            <xsl:apply-templates select="oldconf:Local"/>
            <xsl:text>&#10;</xsl:text>
            <xsl:apply-templates select="oldconf:Global/oldconf:UnixListener"/>
            <xsl:apply-templates select="oldconf:Global/oldconf:TCPListener"/>
            <xsl:text>&#10;    </xsl:text>
            <xsl:comment>
                <xsl:text> This set of components stores sessions and other persistent data in daemon memory. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;    </xsl:text>
            <StorageService type="Memory" id="mem" cleanupInterval="900"/>
            <xsl:text>&#10;    </xsl:text>
            <SessionCache type="StorageService" StorageService="mem" cacheTimeout="{oldconf:Global/oldconf:MemorySessionCache/@cacheTimeout}" inprocTimeout="900" cleanupInterval="900"/>
            <xsl:text>&#10;    </xsl:text>
            <ReplayCache StorageService="mem"/>
            <xsl:text>&#10;    </xsl:text>
            <ArtifactMap artifactTTL="180"/>
            <xsl:text>&#10;&#10;    </xsl:text>
            <xsl:comment>
                <xsl:text> This set of components stores sessions and other persistent data in an ODBC database. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;    </xsl:text>
            <xsl:comment>
                <xsl:text>
    &lt;StorageService type="ODBC" id="db" cleanupInterval="900"&gt;
        &lt;ConnectionString&gt;DRIVER=drivername;SERVER=dbserver;UID=shibboleth;PWD=password;DATABASE=shibboleth;APP=Shibboleth&lt;/ConnectionString&gt;
    &lt;/StorageService&gt;
    &lt;SessionCache type="StorageService" StorageService="db" cacheTimeout="3600" inprocTimeout="900" cleanupInterval="900"/&gt;
    &lt;ReplayCache StorageService="db"/&gt;
    &lt;ArtifactMap StorageService="db" artifactTTL="180"/&gt;
    </xsl:text>
            </xsl:comment>
            <xsl:apply-templates select="oldconf:Local/oldconf:RequestMapProvider"/>
            <xsl:apply-templates select="oldconf:Applications"/>

            <xsl:text>&#10;&#10;    </xsl:text>
            <xsl:comment>
                <xsl:text> Each policy defines a set of rules to use to secure messages. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;    </xsl:text>
            <SecurityPolicies>
                <xsl:text>&#10;        </xsl:text>
                <xsl:comment>
                    <xsl:text> The predefined policy enforces replay/freshness and permits signing and client TLS. </xsl:text>
                </xsl:comment>
                <xsl:text>&#10;        </xsl:text>
                <Policy id="default" validate="false">
                    <xsl:text>&#10;            </xsl:text>
                    <PolicyRule type="MessageFlow" checkReplay="true" expires="60"/>
                    <xsl:text>&#10;            </xsl:text>
                    <PolicyRule type="Conditions">
                    <xsl:text>&#10;                </xsl:text>
                        <PolicyRule type="Audience"/>
                    <xsl:text>&#10;            </xsl:text>
                    </PolicyRule>
                    <PolicyRule type="ClientCertAuth" errorFatal="true"/>
                    <xsl:text>&#10;            </xsl:text>
                    <PolicyRule type="XMLSigning" errorFatal="true"/>
                    <xsl:text>&#10;            </xsl:text>
                    <PolicyRule type="SimpleSigning" errorFatal="true"/>
                    <xsl:text>&#10;        </xsl:text>
                </Policy>
                <xsl:text>&#10;    </xsl:text>
            </SecurityPolicies>
            <xsl:text>&#10;&#10;</xsl:text>
        </SPConfig>
    </xsl:template>
    
    <!-- Turn <Global> into <OutOfProcess> with the ODBC extension commented out. -->
    <xsl:template match="oldconf:Global">
        <xsl:text>&#10;    </xsl:text>
        <OutOfProcess logger="{@logger}">
            <xsl:text>&#10;        </xsl:text>
            <xsl:comment>
                <xsl:text>
        &lt;Extensions&gt;
           &lt;Library path="odbc-store.so" fatal="true"/&gt;
        &lt;/Extensions&gt;
        </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;    </xsl:text>
        </OutOfProcess>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>

    <!-- Turn <Local> into <InProcess> with the <ISAPI> element up a level. -->
    <xsl:template match="oldconf:Local">
        <xsl:text>&#10;    </xsl:text>
        <InProcess logger="{@logger}">
            <xsl:if test="@unsetHeaderValue">
                <xsl:attribute name="unsetHeaderValue"><xsl:value-of select="@unsetHeaderValue"/></xsl:attribute>
            </xsl:if>
            <xsl:apply-templates select="oldconf:Implementation/oldconf:ISAPI"/>
            <xsl:text>&#10;    </xsl:text>
        </InProcess>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>
    <xsl:template match="oldconf:ISAPI">
        <xsl:text>&#10;        </xsl:text>
        <ISAPI>
            <xsl:apply-templates select="@*"/>
            <xsl:for-each select="oldconf:Site">
                <xsl:text>&#10;            </xsl:text>
                <Site>
                    <xsl:apply-templates select="@*"/>
                    <xsl:for-each select="oldconf:Alias">
                        <xsl:text>&#10;                </xsl:text>
                        <Alias><xsl:value-of select="text()"/></Alias>
                    </xsl:for-each>
                    <xsl:text>&#10;            </xsl:text>
                </Site>
            </xsl:for-each>
            <xsl:text>&#10;        </xsl:text>
        </ISAPI>
    </xsl:template>

    <!-- Pull in listeners up to the top level. -->
    <xsl:template match="oldconf:UnixListener">
        <xsl:text>&#10;    </xsl:text>
        <UnixListener address="shibd.sock"/>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>
    <xsl:template match="oldconf:TCPListener">
        <xsl:text>&#10;    </xsl:text>
        <TCPListener address="{@address}" port="{@port}" acl="{@acl}"/>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>

    <!-- Transplant old RequestMap into the new namespace, but just copy all the settings. -->
    <xsl:template match="oldconf:RequestMapProvider">
        <xsl:text>&#10;&#10;    </xsl:text>
        <RequestMapper type="Native">
            <xsl:text>&#10;</xsl:text>
            <xsl:apply-templates select="./*">
                <xsl:with-param name="indent">8</xsl:with-param>
            </xsl:apply-templates>
            <xsl:text>    </xsl:text>
        </RequestMapper>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="oldconf:Applications">
        <xsl:text>&#10;    </xsl:text>
        <ApplicationDefaults id="{@id}" policyId="default" entityID="{@providerId}" homeURL="{@homeURL}" REMOTE_USER="eppn persistent-id targeted-id" signing="false" encryption="false">
            <xsl:attribute name="timeout"><xsl:value-of select="../oldconf:Global/oldconf:MemorySessionCache/@AATimeout"/></xsl:attribute>
            <xsl:attribute name="connectTimeout"><xsl:value-of select="../oldconf:Global/oldconf:MemorySessionCache/@AAConnectTimeout"/></xsl:attribute>
            <xsl:if test="oldconf:CredentialUse/@TLS!=../oldconf:CredentialsProvider/cred:Credentials/cred:FileResolver[1]/@Id">
                <xsl:attribute name="keyName"><xsl:value-of select="oldconf:CredentialUse/@TLS"/></xsl:attribute>
            </xsl:if>
            <xsl:if test="oldconf:CredentialUse/@signedAssertions">
                <xsl:attribute name="requireSignedAssertions"><xsl:value-of select="oldconf:CredentialUse/@signedAssertions"/></xsl:attribute>   
            </xsl:if>
            <xsl:text>&#10;</xsl:text>
            <xsl:apply-templates select="oldconf:Sessions"/>
            <xsl:apply-templates select="oldconf:Errors"/>
            <xsl:apply-templates select="oldconf:CredentialUse"/>
            <xsl:text>&#10;&#10;        </xsl:text>
            <MetadataProvider type="Chaining">
                <xsl:for-each select="oldconf:MetadataProvider|oldconf:FederationProvider">
                    <xsl:text>&#10;            </xsl:text>
                    <MetadataProvider type="XML" file="{@uri}"/>
                </xsl:for-each>
                <xsl:text>&#10;        </xsl:text>
            </MetadataProvider>
            <xsl:text>&#10;&#10;        </xsl:text>
            <xsl:comment>
                <xsl:text> Chain the two built-in trust engines together. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;        </xsl:text>
            <TrustEngine type="Chaining">
                <xsl:text>&#10;            </xsl:text>
                <TrustEngine type="ExplicitKey"/>
                <xsl:text>&#10;            </xsl:text>
                <TrustEngine type="PKIX"/>
                <xsl:text>&#10;        </xsl:text>
            </TrustEngine>
            <xsl:text>&#10;&#10;        </xsl:text>
            <xsl:comment>
                <xsl:text> Map to extract attributes from SAML assertions. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;        </xsl:text>
            <AttributeExtractor type="XML" path="attribute-map.xml"/>
            <xsl:text>&#10;&#10;        </xsl:text>
            <xsl:comment>
                <xsl:text> Use a SAML query if no attributes are supplied during SSO. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;        </xsl:text>
            <AttributeResolver type="Query"/>
            <xsl:text>&#10;&#10;        </xsl:text>
            <xsl:comment>
                <xsl:text> Default filtering policy for recognized attributes, lets other data pass. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;        </xsl:text>
            <AttributeFilter type="XML" path="attribute-policy.xml"/>
            <xsl:text>&#10;&#10;</xsl:text>
       
            <!-- Step up and pull in credentials from the top level. -->
            <xsl:apply-templates select="../oldconf:CredentialsProvider"/>
       
            <xsl:for-each select="oldconf:Application">
                <xsl:text>&#10;        </xsl:text>
                <ApplicationOverride id="{@id}" entityID="{@providerId}" homeURL="{@homeURL}">
                    <xsl:apply-templates select="oldconf:Sessions"/>
                    <xsl:apply-templates select="oldconf:Errors"/>
                    <xsl:apply-templates select="oldconf:CredentialUse"/>
                    <xsl:if test="count(oldconf:MetadataProvider) + count(oldconf:FederationProvider) > 0">
                        <xsl:text>&#10;            </xsl:text>
                        <MetadataProvider type="Chaining">
                        <xsl:for-each select="oldconf:MetadataProvider|oldconf:FederationProvider">
                            <xsl:text>&#10;                </xsl:text>
                            <MetadataProvider type="XML" file="{@uri}"/>
                        </xsl:for-each>
                        <xsl:text>&#10;            </xsl:text>
                        </MetadataProvider>
                    </xsl:if>
                    <xsl:text>&#10;&#10;        </xsl:text>
                </ApplicationOverride>
            </xsl:for-each>
       
            <xsl:text>&#10;&#10;    </xsl:text>
        </ApplicationDefaults>
    </xsl:template>
    
    <xsl:template match="oldconf:Sessions">
        <xsl:text>&#10;        </xsl:text>
        <Sessions exportLocation="http://localhost/{@handlerURL}/GetAssertion">
            <xsl:apply-templates select="@*"/>
            <xsl:text>&#10;&#10;            </xsl:text>
            <xsl:comment>
                <xsl:text>
            SessionInitiators handle session requests and relay them to a Discovery page,
            or to an IdP if possible. Automatic session setup will use the default or first
            element (or requireSessionWith can specify a specific one to use).
            </xsl:text>
            </xsl:comment>
            <xsl:for-each select="oldconf:SessionInitiator">
                <xsl:apply-templates select="."/>
            </xsl:for-each>
            <xsl:text>&#10;&#10;            </xsl:text>
            <xsl:comment>
                <xsl:text>
            md:AssertionConsumerService locations handle specific SSO protocol bindings,
            such as SAML 2.0 POST or SAML 1.1 Artifact. The isDefault and index attributes
            are used when sessions are initiated to determine how to tell the IdP where and
            how to return the response.
            </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <md:AssertionConsumerService Location="/SAML2/POST" index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
            <xsl:text>&#10;            </xsl:text>
            <md:AssertionConsumerService Location="/SAML2/POST-SimpleSign" index="2" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign"/>
            <xsl:text>&#10;            </xsl:text>
            <md:AssertionConsumerService Location="/SAML2/Artifact" index="3" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"/>
            <xsl:text>&#10;            </xsl:text>
            <md:AssertionConsumerService Location="/SAML2/ECP" index="4" Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS"/>
            <xsl:text>&#10;            </xsl:text>
            <md:AssertionConsumerService Location="/SAML/POST" index="5" Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post"/>
            <xsl:text>&#10;            </xsl:text>
            <md:AssertionConsumerService Location="/SAML/Artifact" index="6" Binding="urn:oasis:names:tc:SAML:1.0:profiles:artifact-01"/>
            <xsl:text>&#10;&#10;            </xsl:text>

            <!-- Turn the old local SLO location into the new LogoutInitiator location. -->
            <xsl:variable name="LogoutLocation">
                <xsl:choose>
                    <xsl:when test="md:SingleLogoutService[1]">
                        <xsl:value-of select="md:SingleLogoutService[1]/@Location"/>
                    </xsl:when>
                    <xsl:otherwise>/Logout</xsl:otherwise>
                </xsl:choose>
            </xsl:variable>
           
            <xsl:comment>
            <xsl:text> LogoutInitiators enable SP-initiated local or global/single logout of sessions. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <LogoutInitiator type="Chaining" Location="{$LogoutLocation}" relayState="cookie">
                <xsl:text>&#10;                </xsl:text>
                <LogoutInitiator type="SAML2" template="bindingTemplate.html"/>
                <xsl:text>&#10;                </xsl:text>
                <LogoutInitiator type="Local"/>
                <xsl:text>&#10;            </xsl:text>
            </LogoutInitiator>
            <xsl:text>&#10;&#10;            </xsl:text>

            <xsl:comment>
            <xsl:text> md:SingleLogoutService locations handle single logout (SLO) protocol messages. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <md:SingleLogoutService Location="/SLO/SOAP" Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"/>
            <xsl:text>&#10;            </xsl:text>
            <md:SingleLogoutService Location="/SLO/Redirect" conf:template="bindingTemplate.html" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>
            <xsl:text>&#10;            </xsl:text>
            <md:SingleLogoutService Location="/SLO/POST" conf:template="bindingTemplate.html" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
            <xsl:text>&#10;            </xsl:text>
            <md:SingleLogoutService Location="/SLO/Artifact" conf:template="bindingTemplate.html" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"/>
            <xsl:text>&#10;&#10;            </xsl:text>

            <xsl:comment>
            <xsl:text> md:ManageNameIDService locations handle NameID management (NIM) protocol messages. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <md:ManageNameIDService Location="/NIM/SOAP" Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"/>
            <xsl:text>&#10;            </xsl:text>
            <md:ManageNameIDService Location="/NIM/Redirect" conf:template="bindingTemplate.html" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"/>
            <xsl:text>&#10;            </xsl:text>
            <md:ManageNameIDService Location="/NIM/POST" conf:template="bindingTemplate.html" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"/>
            <xsl:text>&#10;            </xsl:text>
            <md:ManageNameIDService Location="/NIM/Artifact" conf:template="bindingTemplate.html" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"/>
            <xsl:text>&#10;&#10;            </xsl:text>

            <xsl:comment>
            <xsl:text>
            md:ArtifactResolutionService locations resolve artifacts issued when using the
            SAML 2.0 HTTP-Artifact binding on outgoing messages, generally uses SOAP.
            </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <md:ArtifactResolutionService Location="/Artifact/SOAP" index="1" Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP"/>
            <xsl:text>&#10;&#10;            </xsl:text>

            <xsl:comment>
            <xsl:text> Extension service that generates "approximate" metadata based on SP configuration. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <Handler type="MetadataGenerator" Location="/Metadata" signing="false"/>
            <xsl:text>&#10;&#10;            </xsl:text>
           
            <xsl:comment>
            <xsl:text> Status reporting service. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <Handler type="Status" Location="Status" acl="127.0.0.1"/>
            <xsl:text>&#10;&#10;            </xsl:text>

            <xsl:comment>
            <xsl:text> Session diagnostic service. </xsl:text>
            </xsl:comment>
            <xsl:text>&#10;            </xsl:text>
            <Handler type="Session" Location="/Session"/>
            <xsl:text>&#10;        </xsl:text>
        </Sessions>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>
    
    <xsl:template match="oldconf:SessionInitiator">
        <xsl:text>&#10;&#10;            </xsl:text>
        <SessionInitiator type="Chaining" Location="{@Location}" acsByIndex="false" relayState="cookie">
            <xsl:if test="@id">
                <xsl:attribute name="id"><xsl:value-of select="@id"/></xsl:attribute>
            </xsl:if>
            <xsl:if test="@isDefault">
                <xsl:attribute name="isDefault"><xsl:value-of select="@isDefault"/></xsl:attribute>
            </xsl:if>
            <xsl:if test="@Location=../oldconf:SessionInitiator[1]/@Location">
                <xsl:if test="$idp">
                    <xsl:attribute name="entityID"><xsl:value-of select="$idp"/></xsl:attribute>
                </xsl:if>
            </xsl:if>
            <xsl:text>&#10;                </xsl:text>
            <SessionInitiator type="SAML2" acsIndex="1" ECP="true" template="bindingTemplate.html"/>
            <xsl:text>&#10;                </xsl:text>
            <SessionInitiator type="Shib1" acsIndex="5"/>
            <xsl:if test="@wayfURL">
                <xsl:if test="@wayfBinding='urn:mace:shibboleth:1.0:profiles:AuthnRequest'">
                    <xsl:text>&#10;                </xsl:text>
                    <SessionInitiator type="WAYF" URL="{@wayfURL}"/>
                </xsl:if>
            </xsl:if>
            <xsl:text>&#10;            </xsl:text>
        </SessionInitiator>
    </xsl:template>
    
    <!-- Map <Errors> element across, adding logout templates. -->
    <xsl:template match="oldconf:Errors">
        <xsl:text>&#10;        </xsl:text>
        <Errors>
            <xsl:apply-templates select="@*"/>
            <xsl:text>&#10;        </xsl:text>
        </Errors>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>
    
    <!-- Map <CredentialUse> element content into relying party overrides. -->
    <xsl:template match="oldconf:CredentialUse">
        <xsl:for-each select="oldconf:RelyingParty">
            <xsl:if test="@TLS">
                <xsl:text>&#10;        </xsl:text>
                <RelyingParty Name="{@Name}" keyName="{@TLS}"/>
            </xsl:if>
        </xsl:for-each>
    </xsl:template>

    <!-- Map legacy <FileResolver> elements to CredentialResolver plugins. -->
    <xsl:template match="oldconf:CredentialsProvider">
        <xsl:choose>
            <xsl:when test="count(//cred:FileResolver) > 1">
                <xsl:text>        </xsl:text>
                <CredentialResolver type="Chaining">
                    <xsl:text>&#10;</xsl:text>
                    <xsl:apply-templates select="//cred:FileResolver">
                        <xsl:with-param name="indent">12</xsl:with-param>
                    </xsl:apply-templates>
                    <xsl:text>        </xsl:text>
                </CredentialResolver>
                <xsl:text>&#10;</xsl:text>
            </xsl:when>
            <xsl:otherwise>
                <xsl:apply-templates select="//cred:FileResolver">
                    <xsl:with-param name="indent">8</xsl:with-param>
                </xsl:apply-templates>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
    <xsl:template match="cred:FileResolver">
        <xsl:param name="indent"/>
        <xsl:value-of select="substring($spaces,0,$indent+1)"/>
        <CredentialResolver type="File" key="{cred:Key/cred:Path/text()}" certificate="{cred:Certificate/cred:Path/text()}" keyName="{@Id}"/>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>

    <!-- Generic rule to pass through all element node content while converting the namespace. -->
    <xsl:template match="oldconf:RequestMap|oldconf:Host|oldconf:HostRegex|oldconf:Path|oldconf:PathRegex|oldconf:htaccess|oldconf:AccessControl|oldconf:AND|oldconf:OR|oldconf:NOT">
        <xsl:param name="indent"/>
        <xsl:value-of select="substring($spaces,0,$indent+1)"/>
        <xsl:element name="{name()}">
            <xsl:apply-templates select="@*"/>
            <xsl:text>&#10;</xsl:text>
            <xsl:apply-templates select="./*">
                <xsl:with-param name="indent" select="$indent + 4"/>
            </xsl:apply-templates>
            <xsl:value-of select="substring($spaces,0,$indent+1)"/>
        </xsl:element>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>

    <!-- Generic rule to pass through all attributes plus text content while converting the namespace. -->
    <xsl:template match="oldconf:Rule">
        <xsl:param name="indent"/>
        <xsl:value-of select="substring($spaces,0,$indent+1)"/>
        <xsl:element name="{name()}">
            <xsl:apply-templates select="@*"/>
            <xsl:value-of select="text()"/>
        </xsl:element>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>

    <!-- Generic rule to pass through an attribute unmodified. -->
    <xsl:template match="@*">
        <xsl:attribute name="{name()}"><xsl:value-of select="."/></xsl:attribute>
    </xsl:template>

    <!-- Strips additional text nodes out of document. -->
    <xsl:template match="text()"/>

</xsl:stylesheet>
