package com.instaclustr.cassandra.ldap.auth;

import java.util.Properties;

import com.instaclustr.cassandra.ldap.hash.Hasher;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;

public abstract class LDAPPasswordRetriever implements PasswordRetriever
{

    protected ClientState clientState;
    protected Hasher hasher;
    protected Properties properties;

    public abstract void setup() throws ConfigurationException;

    public void init(ClientState clientState)
    {
        this.clientState = clientState;
    }

    public void init(ClientState clientState, Hasher hasher, Properties properties)
    {
        this.init(clientState);
        this.clientState = clientState;
        this.hasher = hasher;
        this.properties = properties;

        setup();
    }
}
