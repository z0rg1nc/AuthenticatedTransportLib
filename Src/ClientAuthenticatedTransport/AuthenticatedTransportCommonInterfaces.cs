using System;

namespace BtmI2p.AuthenticatedTransport
{
    public static class AuthenticatedTransportCommonConstants
    {
        public static readonly TimeSpan DefaultAuthDuration 
            = TimeSpan.FromMinutes(15.0f);

        public static readonly TimeSpan DefaultAuthDataLifeTime
            = TimeSpan.FromMinutes(10.0);

        public static readonly TimeSpan RenewBeforeEnd = TimeSpan.FromMinutes(3.5d);
        public const int RpcRethrowableExceptionAuthFailedErrorCode = 1100000;
        public static readonly TimeSpan TimeoutOnAuthFailed = TimeSpan.FromSeconds(5.0d);
    }
}
