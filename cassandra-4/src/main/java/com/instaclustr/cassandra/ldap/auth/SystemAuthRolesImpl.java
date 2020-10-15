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
package com.instaclustr.cassandra.ldap.auth;

import static java.lang.String.format;
import static org.apache.cassandra.db.ConsistencyLevel.ONE;

import com.google.common.collect.Lists;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;

public class SystemAuthRolesImpl extends SystemAuthRoles
{

    /**
     * Check if a particular role exists in system.auth
     *
     * @param dn user's distinguished name.
     * @return True if DN exists in C* roles otherwise false
     */
    public boolean roleMissing(String dn)
    {
        final SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(format(SELECT_ROLE_STATEMENT,
                                                                                             "system_auth",
                                                                                             AuthKeyspace.ROLES),
                                                                                      getClientState());

        final ResultMessage.Rows rows = selStmt.execute(new QueryState(getClientState()),
                                                        QueryOptions.forInternalCalls(ONE,
                                                                                      Lists.newArrayList(ByteBufferUtil.bytes(dn))),
                                                        System.nanoTime());

        return rows.result.isEmpty();
    }

    public void createRole(String roleName)
    {
        assert getClientState() != null;

        final CreateRoleStatement createStmt = (CreateRoleStatement) QueryProcessor.getStatement(format(CREATE_ROLE_STATEMENT_WITH_LOGIN, roleName), getClientState());

        createStmt.execute(new QueryState(getClientState()),
                           QueryOptions.forInternalCalls(ONE, Lists.newArrayList(ByteBufferUtil.bytes(roleName))),
                           System.nanoTime());
    }
}
