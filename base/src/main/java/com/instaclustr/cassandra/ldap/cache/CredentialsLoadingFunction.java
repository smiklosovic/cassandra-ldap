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
package com.instaclustr.cassandra.ldap.cache;

import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import com.instaclustr.cassandra.ldap.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialsLoadingFunction implements Function<User, String>
{

    private static final Logger logger = LoggerFactory.getLogger(CredentialsLoadingFunction.class);

    private Function<User, String> passwordAuthLoadingFunction;

    private Function<User, String> ldapAuthLoadingFunction;

    private String namingAttributeValue;

    public CredentialsLoadingFunction(final Function<User, String> passwordAuthLoadingFunction,
                                      final Function<User, String> ldapAuthLoadingFunction,
                                      final String namingAttributeValue)
    {
        this.passwordAuthLoadingFunction = passwordAuthLoadingFunction;
        this.ldapAuthLoadingFunction = ldapAuthLoadingFunction;
        this.namingAttributeValue = namingAttributeValue;
    }

    public Function<User, String> getPasswordAuthLoadingFunction()
    {
        return passwordAuthLoadingFunction;
    }

    public Function<User, String> getLdapAuthLoadingFunction()
    {
        return ldapAuthLoadingFunction;
    }

    @Override
    public String apply(User user)
    {
        // in case there are two logins of same name (e.g. admin in LDAP and admin in C*),
        // in order to distinguish them, if you want to login with LDAP user, you have to
        // specify its full account name, e.g
        // cqlsh -u cn=admin,dn=example,dn=org
        //
        // in case user specifies just "admin" as login name, it will try to authenticate
        // both against database first and if not successful, against LDAP.
        if (user.getUsername() != null && user.getUsername().contains(namingAttributeValue + "="))
        {
            logger.debug("Doing LDAP authentication against " + user.getUsername());

            Optional<String> username = Stream.of(user.getUsername().split(","))
                .filter(component -> component.startsWith(namingAttributeValue + "="))
                .findFirst()
                .filter(component -> component.split("=").length == 2)
                .map(component -> component.split("=")[1]);

            if (username.isPresent())
            {
                return getLdapAuthLoadingFunction().apply(new User(username.get(), user.getPassword()));
            }
        }

        try
        {
            logger.debug("Doing password authentication against " + user.getUsername());

            return getPasswordAuthLoadingFunction().apply(user);
        } catch (final Exception ex)
        {
            logger.debug("Doing LDAP authentication in exception block against " + user.getUsername());

            // we are in this catch block because
            // 1) there was not such role found in Cassandra DB hence we have to go against LDAP
            // 2) there was such role but that role does not have password in the database
            //    so we have nothing to check against so we need to do authentication against LDAP.
            //    This happens e.g. with admin user which is created but it does not have its password hashed there since it is in LDAP
            //    This also means what we will be able to login with "cassandra:cassandra" combination without the necessity to ever reach LDAP server.
            //
            // If there is such username and password in the database, we will never reach this catch and
            // from user perspective it acts as if there was not any LDAP server at all, we are effectively doing PasswordAuthenticator

            return getLdapAuthLoadingFunction().apply(user);
        }
    }
}
