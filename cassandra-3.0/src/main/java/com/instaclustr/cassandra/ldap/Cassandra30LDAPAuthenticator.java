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

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.NAMING_ATTRIBUTE_PROP;
import static java.lang.String.format;

import java.util.concurrent.TimeUnit;

import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.common.util.concurrent.Uninterruptibles;
import com.instaclustr.cassandra.ldap.auth.CassandraPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.DefaultLDAPServer;
import com.instaclustr.cassandra.ldap.auth.LDAPPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import com.instaclustr.cassandra.ldap.cache.CredentialsLoadingFunction;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.CassandraAuthorizer;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
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
public class Cassandra30LDAPAuthenticator extends AbstractLDAPAuthenticator
{

    private static final Logger logger = LoggerFactory.getLogger(Cassandra30LDAPAuthenticator.class);

    private CredentialsLoadingFunction credentialsLoadingFunction;

    public void setup()
    {
        if (!(CassandraAuthorizer.class.isAssignableFrom(DatabaseDescriptor.getAuthorizer().getClass())))
        {
            throw new ConfigurationException(format("%s only works with %s",
                                                    Cassandra30LDAPAuthenticator.class.getCanonicalName(),
                                                    CassandraAuthorizer.class.getCanonicalName()));
        }

        clientState = ClientState.forInternalCalls();

        systemAuthRoles = getService(SystemAuthRoles.class, null);
        systemAuthRoles.setClientState(clientState);

        systemAuthRoles.waitUntilRoleIsInitialised(System.getProperty("cassandra.ldap.admin.user", "cassandra"));

        if (!loggedIn)
        {
            // In case operator deletes cassandra role, in order to log in with a user different from cassandra,
            // one has to set below system property for Cassandra process upon start.
            // This user has to be superuser in order to be able to create roles.
            // You have to specify what is basically in ldap.properties
            // under service_dn, e.g "-Dcassandra.ldap.admin.user=cn=admin,dc=example,dc=org"
            // This name maps to system_auth.roles.role field and it has to be already present so operator
            // will likely log in with LDAP admin first in order to have that entry present in system_auth.roles

            assert clientState != null;

            while (true)
            {
                try
                {
                    clientState.login(new AuthenticatedUser(System.getProperty("cassandra.ldap.admin.user", "cassandra")));
                    break;
                } catch (final Exception ex)
                {
                    logger.error("failed to log in in setup, sleeping for 5 seconds ");
                    Uninterruptibles.sleepUninterruptibly(5, TimeUnit.SECONDS);
                }
            }

            if (properties.getProperty(LDAP_DN) != null)
            {
                systemAuthRoles.createRole(properties.getProperty(LDAP_DN), true);
            }

            loggedIn = true;
        }

        final CassandraPasswordRetriever cassandraPasswordRetriever = getService(CassandraPasswordRetriever.class, null);
        cassandraPasswordRetriever.init(clientState);

        final LDAPPasswordRetriever ldapPasswordRetriever = getService(LDAPPasswordRetriever.class, DefaultLDAPServer.class);
        try
        {
            ldapPasswordRetriever.init(clientState, hasher, properties);
        } catch (ConfigurationException e)
        {
            logger.warn(format("Not possible to connect to LDAP server as user %s.", properties.getProperty(LDAP_DN)), e);
        }

        credentialsLoadingFunction = new CredentialsLoadingFunction(cassandraPasswordRetriever::retrieveHashedPassword,
                                                                    ldapPasswordRetriever::retrieveHashedPassword,
                                                                    properties.getProperty(NAMING_ATTRIBUTE_PROP));

        logger.info("{} was initialised", Cassandra30LDAPAuthenticator.class.getName());
    }

    @Override
    public AuthenticatedUser authenticate(final String username, final String loginPassword)
    {
        try
        {
            final User user = new User(username, loginPassword);

            final String userPassword = credentialsLoadingFunction.apply(user);

            if (userPassword != null)
            {
                if (!hasher.checkPasswords(loginPassword, userPassword))
                {

                    if (user.getLdapDN() == null)
                    {
                        throw new AuthenticationException("invalid username/password");
                    }
                }

                final String loginName = user.getLdapDN() == null ? user.getUsername() : user.getLdapDN();

                if (user.getLdapDN() != null)
                {
                    systemAuthRoles.createRole(user.getLdapDN(), false);
                } else if (user.getUsername().startsWith(properties.getProperty(NAMING_ATTRIBUTE_PROP)))
                {
                    systemAuthRoles.createRole(user.getUsername(), false);
                }

                return new AuthenticatedUser(loginName);
            }
        } catch (final UncheckedExecutionException ex)
        {
            if (ex.getCause() instanceof LDAPAuthFailedException)
            {
                final LDAPAuthFailedException ldex = (LDAPAuthFailedException) ex.getCause();

                logger.warn("Failed login for {}, reason was {}", username, ex.getMessage());

                throw new AuthenticationException(format(
                    "Failed to authenticate with directory server, user may not exist: %s",
                    ldex.getMessage()));
            } else
            {
                throw ex;
            }
        } catch (final AuthenticationException ex)
        {
            throw ex;
        } catch (final Exception ex)
        {
            throw new AuthenticationException(format("Could not authenticate: %s", ex.getMessage()));
        }

        return null; // should never
    }
}