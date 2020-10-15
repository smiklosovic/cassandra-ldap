package com.instaclustr.cassandra.ldap;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import com.google.common.collect.Lists;
import com.google.common.util.concurrent.Uninterruptibles;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.CassandraAuthorizer;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Uses JNDI to authenticate to an LDAP server. On successful authentication a Cassandra role is created for the provided
 * user. This user is configured without a password, so if you disable Authenticator or switch Authenticator any user
 * will be usable by anyone (this is no different to switching a single node to AllowAllAuthenticator).
 *
 * Users that are disabled in LDAP can only be cleaned up manually, however this is not typically necessary as long as you
 * keep using LDAPAuthenticator, they will just needlessly fill up system_auth. As long as they are disabled in your LDAP
 * server, they cannot be authenticated with Cassandra.
 *

 */
public class LDAPAuthenticator implements IAuthenticator
{

    private static final Logger logger = LoggerFactory.getLogger(LDAPAuthenticator.class);

    // Ldap URI including DN
    public final static String LDAP_URI_PROP = "ldap_uri";
    public final static String CONTEXT_FACTORY_PROP = "context_factory";
    // Initial connection to LDAP can be anonymous if it's enabled. Won't allow you to connect to C* anonymously.
    public final static String ANONYMOUS_ACCESS_PROP = "anonymous_access";

    public final static String DEFAULT_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    public final static String DEFAULT_SERVICE_ROLE = "_LDAPAUTH_";
    public final static String ROLE = "role";
    // If no anonymous access a default DN and password is required.
    public final static String LDAP_DN = "service_dn";
    public final static String PASSWORD_KEY = "service_password";
    public final static String CREATE_ROLE_STMT = "CREATE ROLE \"%s\" WITH LOGIN = true";
    public final static String FIND_USER_STMT = "SELECT %s FROM %s.%s where role = ?";
    public final static String LDAP_PROPERTIES_FILE = "ldap.properties.file";
    public final static String LDAP_PROPERTIES_FILENAME = "ldap.properties";
    // Just to support those not using "cn"
    public final static String NAMING_ATTRIBUTE_PROP = "ldap_naming_attribute";

    public final static String DEFAULT_SUPERUSER_NAME = "cassandra";

    private static ClientState state;

    private String serviceDN;
    private String servicePass;

    private final Set<String> existingUsers = new HashSet<>();
    private Properties properties;
    // Use the service context for the initial connection so we can search for users DNs.
    private DirContext serviceContext;
    // Keeps track of usernames to DN's to reduce trips to the LDAP server
    private Map<String, String> usernameToDN = new HashMap<>();

    private static final byte NUL = 0;

    public boolean requireAuthentication()
    {
        return true;
    }

    public Set<? extends IResource> protectedResources()
    {
        return Collections.emptySet();
    }

    public void validateConfiguration() throws ConfigurationException
    {
        properties = new Properties();
        properties.put(Context.SECURITY_AUTHENTICATION, "simple");
        properties.put("com.sun.jndi.ldap.read.timeout", "1000");
        properties.put("com.sun.jndi.ldap.connect.timeout", "2000");
        properties.put("com.sun.jndi.ldap.connect.pool", "true");

        try (FileInputStream input = new FileInputStream(System.getProperty(LDAP_PROPERTIES_FILE, LDAP_PROPERTIES_FILENAME)))
        {
            properties.load(input);
        } catch (IOException e)
        {
            throw new ConfigurationException("Could not open ldap configuration file", e);
        }

        if (!properties.containsKey(LDAP_URI_PROP))
        {
            throw new ConfigurationException(String.format("{0} MUST be set in the configuration file.", LDAP_URI_PROP));
        }

        properties.put(Context.INITIAL_CONTEXT_FACTORY, properties.getProperty(CONTEXT_FACTORY_PROP, DEFAULT_CONTEXT_FACTORY));
        properties.put(Context.PROVIDER_URL, properties.getProperty(LDAP_URI_PROP));
    }

    public void setup()
    {
        state = ClientState.forInternalCalls();
        try
        {
            state.login(new AuthenticatedUser(DEFAULT_SUPERUSER_NAME));
        } catch (AuthenticationException a)
        {
            // If we got here it was likely the first node in the clusters first startup, and we need to
            // sleep to ensure superuser and auth has been set up before we try login.
            Uninterruptibles.sleepUninterruptibly(AuthKeyspace.SUPERUSER_SETUP_DELAY + 100, TimeUnit.MILLISECONDS);
            state.login(new AuthenticatedUser(DEFAULT_SUPERUSER_NAME));
        }

        if (!(CassandraAuthorizer.class.isAssignableFrom(DatabaseDescriptor.getAuthorizer().getClass())))
        {
            throw new ConfigurationException("LDAPAuthenticator only works with CassandraAuthorizer");
        }
        try
        {
            if (properties.getProperty(ANONYMOUS_ACCESS_PROP, "false").equalsIgnoreCase("true"))
            {
                // Anonymous
                serviceContext = new InitialDirContext(properties);
                state.login(new AuthenticatedUser(DEFAULT_SERVICE_ROLE));
            } else
            {
                //connect with provided DN/PW
                serviceDN = properties.getProperty(LDAP_DN);
                servicePass = properties.getProperty(PASSWORD_KEY);
                if (serviceDN == null || servicePass == null)
                {
                    throw new ConfigurationException(String.format("You must specify both %s and %s if %s is false.", LDAP_DN, PASSWORD_KEY, ANONYMOUS_ACCESS_PROP));
                }
                properties.put(Context.SECURITY_PRINCIPAL, serviceDN);
                properties.put(Context.SECURITY_CREDENTIALS, servicePass);

                serviceContext = new InitialDirContext(properties);

                if (!userExists(serviceDN))
                {
                    QueryProcessor.process(String.format("INSERT INTO %s.%s (role, is_superuser, can_login) " +
                                                             "VALUES ('%s', true, true)",
                                                         AuthKeyspace.NAME,
                                                         AuthKeyspace.ROLES,
                                                         serviceDN
                                           ),
                                           ConsistencyLevel.ONE
                    );
                }
            }
        } catch (NamingException n)
        {
            throw new ConfigurationException("Failed to connect to LDAP server.", n);
        }
    }

    /**
     * Generate a table of properties for connecting to LDAP server using JNDI
     * @return Table containing Context.INITIAL_CONTEXT_FACTORY, Context.PROVIDER_URL and Context.SECURITY_AUTHENTICATION set.
     */
    public Hashtable<String, String> getUserEnv()
    {
        Hashtable<String, String> env = new Hashtable<String, String>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, properties.getProperty(LDAP_URI_PROP));
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        return env;
    }

    /**
     * Fetch a DN for a specific user
     * @param user Username (CN)
     * @return DN for user
     * @throws NamingException
     */
    private String getUid(String user) throws NamingException
    {
        if (usernameToDN.containsKey(user))
        {
            return usernameToDN.get(user);
        }

        if (serviceContext == null)
        {
            throw new ConfigurationException("LDAP server connection was not initialised");
        }

        logger.debug("Connected to LDAP server {}", properties.get(LDAP_URI_PROP));

        String filter = "(" + properties.getOrDefault(NAMING_ATTRIBUTE_PROP, "cn") + "=" + user + ")";
        SearchControls ctrl = new SearchControls();
        ctrl.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration answer = serviceContext.search("", filter, ctrl);

        String dn;
        if (answer.hasMore())
        {
            SearchResult result = (SearchResult) answer.next();
            dn = result.getNameInNamespace();
        } else
        {
            dn = null;
        }

        answer.close();
        usernameToDN.put(user, dn);
        return dn;
    }

    /**
     * Authenticate to LDAP server as provided DN
     * @param user {@link User} to authenticate
     * @return True if we successfully authenticated.
     * @throws NamingException if authentication fails or other error occurs.
     */
    private String authDN(User user) throws NamingException
    {
        Hashtable env = getUserEnv();
        env.put(Context.SECURITY_PRINCIPAL, user.username);
        env.put(Context.SECURITY_CREDENTIALS, user.password);
        DirContext ctx = null;
        try
        {
            ctx = new InitialDirContext(env);
        } finally
        {
            if (ctx != null)
            {
                try
                {
                    ctx.close();
                } catch (NamingException n)
                {
                }
            }
        }
        return user.password;
    }

    /**
     * Authenticate a user/password combo to the configured LDAP server. On the first successful auth a corresponding
     * C* role will be created.
     * @param username Username portion of the CN or UID. E.g "James Hook" in cn=James Hook,ou=people,o=sevenSeas
     * @param password Corresponding password
     * @return {@link AuthenticatedUser} for the DN as stored in C*.
     * @throws AuthenticationException when auth with LDAP server fails.
     */
    public AuthenticatedUser authenticate(String username, String password) throws AuthenticationException
    {
        String dn;

        try
        {
            dn = getUid(username);
            if (dn == null)
            {
                throw new AuthenticationException("Could not authenticate to directory server using provided credentials");
            }
            logger.trace("DN for user {}: {}", username, dn);

            User user = new User(dn, password);

            authDN(user);

            if (!userExists(dn))
            {
                logger.debug("DN {} doesn't exist in {}.{}, creating new user", dn, AuthKeyspace.NAME, AuthKeyspace.ROLES);
                createRole(dn);
            }

            return new AuthenticatedUser(dn);
        } catch (javax.naming.AuthenticationException e)
        {
            logger.warn("Failed login from {}, reason was {}", username, e.getMessage());
            throw new AuthenticationException("Failed to authenticate with directory server, user may not exist");
        } catch (NamingException e)
        {
            throw new SecurityException("Could not authenticate to the LDAP directory", e);
        }

    }

    public static void createRole(String dn)
    {
        CreateRoleStatement createStmt = (CreateRoleStatement) QueryProcessor.getStatement(String.format(CREATE_ROLE_STMT, dn), state).statement;
        createStmt.execute(new QueryState(state),
                           QueryOptions.forInternalCalls(ConsistencyLevel.ONE,
                                                         Lists.newArrayList(ByteBufferUtil.bytes(dn))));
    }

    /**
     * Check if a particular role exists in system.auth
     * @param dn user's distinguished name.
     * @return True if DN exists in C* roles otherwise false
     */
    private boolean userExists(String dn)
    {
        // To avoid doing a select every auth we store previously checked users in mem
        if (existingUsers.contains(dn))
        {
            return true;
        }

        SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(String.format(FIND_USER_STMT, ROLE, AuthKeyspace.NAME, AuthKeyspace.ROLES), state).statement;
        ResultMessage.Rows rows = selStmt.execute(new QueryState(state),
                                                  QueryOptions.forInternalCalls(ConsistencyLevel.ONE, Lists.newArrayList(ByteBufferUtil.bytes(dn))));
        if (rows.result.isEmpty())
        {
            return false;
        } else
        {
            existingUsers.add(dn);
            return true;
        }
    }

    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {
        return new PlainTextSaslAuthenticator();
    }

    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        String username = credentials.get(LDAP_DN);
        if (username == null)
        {
            throw new AuthenticationException(String.format("Required key '%s' is missing", LDAP_DN));
        }

        String password = credentials.get(PASSWORD_KEY);
        if (password == null)
        {
            throw new AuthenticationException(String.format("Required key '%s' is missing for provided username %s", PASSWORD_KEY, username));
        }

        return authenticate(username, password);
    }

    private class PlainTextSaslAuthenticator implements SaslNegotiator
    {

        private boolean complete = false;
        private String username;
        private String password;

        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
        {
            decodeCredentials(clientResponse);
            complete = true;
            return null;
        }

        public boolean isComplete()
        {
            return complete;
        }

        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
        {
            if (!complete)
            {
                throw new AuthenticationException("SASL negotiation not complete");
            }
            return authenticate(username, password);
        }

        /**
         * SASL PLAIN mechanism specifies that credentials are encoded in a
         * sequence of UTF-8 bytes, delimited by 0 (US-ASCII NUL).
         * The form is : {code}authzId<NUL>authnId<NUL>password<NUL>{code}
         * authzId is optional, and in fact we don't care about it here as we'll
         * set the authzId to match the authnId (that is, there is no concept of
         * a user being authorized to act on behalf of another with this IAuthenticator).
         *
         * @param bytes encoded credentials string sent by the client
         * @throws org.apache.cassandra.exceptions.AuthenticationException if either the
         *         authnId or password is null
         */
        private void decodeCredentials(byte[] bytes) throws AuthenticationException
        {
            logger.trace("Decoding credentials from client token");
            byte[] user = null;
            byte[] pass = null;
            int end = bytes.length;
            for (int i = bytes.length - 1; i >= 0; i--)
            {
                if (bytes[i] == NUL)
                {
                    if (pass == null)
                    {
                        pass = Arrays.copyOfRange(bytes, i + 1, end);
                    } else if (user == null)
                    {
                        user = Arrays.copyOfRange(bytes, i + 1, end);
                    }
                    end = i;
                }
            }

            if (pass == null)
            {
                throw new AuthenticationException("Password must not be null");
            }
            if (user == null)
            {
                throw new AuthenticationException("Authentication ID must not be null");
            }

            username = new String(user, StandardCharsets.UTF_8);
            password = new String(pass, StandardCharsets.UTF_8);
        }
    }

    public static class User
    {

        public final String username;
        public String password;

        User(String name, String pass)
        {
            username = name;
            password = pass;
        }

        @Override
        public boolean equals(Object obj)
        {
            if (obj == null)
            {
                return false;
            }
            final User other = (User) obj;

            return this.username.equals(other.username);
        }
    }
}