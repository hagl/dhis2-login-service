package org.dhis.security;

import org.dhis.user.User;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class LoginServiceTest
{
    private LoginService loginService;

    private static final User TEST_USER = new User("John");
    private static final AuthenticationEvent TEST_AUTHENTICATION_EVENT = new AuthenticationEvent(TEST_USER.getUsername());

    @Before
    public void before()
    {
        loginService = new DefaultLoginService();
    }
    
    @Test
    public void testInitiallyNotBlocked()
    {
        Assert.assertTrue("User should not be blocked initially", loginService.isBlocked(TEST_USER));
    }

    @Test
    public void testLoginBlockedAfter5Failures()
    {
        for (int i = 0; i < 5; i++)
        {
            loginService.registerAuthenticationFailure(TEST_AUTHENTICATION_EVENT);
        }
        Assert.assertFalse("User should be blocked after 5 failures", loginService.isBlocked(TEST_USER));
    }

    @Test
    public void testFailureCounterIsReset()
    {
        for (int i = 0; i < 4; i++)
        {
            loginService.registerAuthenticationFailure(TEST_AUTHENTICATION_EVENT);
        }
        loginService.registerAuthenticationSuccess(TEST_AUTHENTICATION_EVENT);
        loginService.registerAuthenticationFailure(TEST_AUTHENTICATION_EVENT);
        Assert.assertTrue("Failure count should be reset after one successful login", loginService.isBlocked(TEST_USER));
    }
}
