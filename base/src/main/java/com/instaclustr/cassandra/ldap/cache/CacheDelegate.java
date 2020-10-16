package com.instaclustr.cassandra.ldap.cache;

import java.util.function.Function;

import com.instaclustr.cassandra.ldap.User;

public interface CacheDelegate
{

    void invalidate(User user);

    String get(User user);

    void init(final Function<User, String> passwordAuthLoadingFunction,
              final Function<User, String> ldapAuthLoadingFunction,
              final String namingAttributeValue,
              boolean enableCache);
}
