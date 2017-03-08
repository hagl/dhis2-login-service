package org.dhis.security;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.dhis.user.User;

import com.github.benmanes.caffeine.cache.LoadingCache;

import java.util.concurrent.TimeUnit;

public class DefaultLoginService
    implements LoginService
{
    /**
     * Cache for login attempts where usernames are keys and login attempts are values.
     * Entries expire after 1 hour after the last write to reset the login attempts.
     *
     * <p> However this has the following implications: <ul>
     * <li>After 5 failed attempts a user is only blocked for 1 hour and not permanently</li>
     * <li>If a user makes an 5 attempts with a 59 minute break between each of them,
     *    he will still be blocked although he only did 2 failed attempts within each 1 hour timeframe
     *    Implementing the requirement exactly would require a more  sophisticated implementation that
     *    keeps track of the timestamps of the login attempts</li></ul>
     */
    private final LoadingCache<String, Integer> USERNAME_LOGIN_ATTEMPTS_CACHE =
            Caffeine.newBuilder().expireAfterWrite(1, TimeUnit.HOURS).build(username -> 0);

    @Override
    public void registerAuthenticationFailure( AuthenticationEvent event )
    {
        // it is important to increment the login attempts atomically using the ConcurrentMap.compute method,
        // otherwise concurrent brute force attacks could  create race conditions that allow more then 5 attempts
        USERNAME_LOGIN_ATTEMPTS_CACHE.asMap().compute(event.getUsername(), (__, count) -> count != null ? count + 1 : 1);
    }

    @Override
    public void registerAuthenticationSuccess( AuthenticationEvent event )
    {
        USERNAME_LOGIN_ATTEMPTS_CACHE.invalidate(event.getUsername());
    }

    @Override
    public boolean isBlocked( User user )
    {
        return USERNAME_LOGIN_ATTEMPTS_CACHE.get(user.getUsername()) < 5;
    }
}
