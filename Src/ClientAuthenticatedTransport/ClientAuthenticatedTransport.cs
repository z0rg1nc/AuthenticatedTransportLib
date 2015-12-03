using System;
using System.Collections.Generic;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BtmI2p.JsonRpcHelpers.Client;
using BtmI2p.MiscUtils;
using BtmI2p.Newtonsoft.Json.Linq;
using BtmI2p.ObjectStateLib;
using LinFu.DynamicProxy;
using NLog;

namespace BtmI2p.AuthenticatedTransport
{
    public class ServerAuthenticatedFuncsForClient
    {
        //In, ClientGuid, Out
        public Func<byte[], Guid, Task<byte[]>> ProcessRequest;
        public Func<Task<List<JsonRpcServerMethodInfo>>> GetMethodInfos;
        //ClientGuid, AsymmetricEncrypt(AuthHashBytes)
        public Func<Guid, Task<byte[]>> GetAuthData;
        //ClientGuid, Hash(AuthHashBytes)
        public Func<Guid, byte[], Task<bool>> AuthMe;
        // AsymmetricEncrypt(AuthHashBytes) => AuthHashBytes
        public Func<byte[], Task<byte[]>> DecryptAuthDataFunc; 
    }

    public class ClientAuthenticatedTransportSettings
    {
        public TimeSpan RenewAuthenticationInterval =
            TimeSpan.FromMinutes(10.0);
    }

    public class ClientAuthenticatedTransport<T1> : IInvokeWrapper, IMyAsyncDisposable
        where T1 : class
    {
        private ClientAuthenticatedTransport()
        {
        }

        private ServerAuthenticatedFuncsForClient _transport;
        private Guid _clientId;
        private ClientAuthenticatedTransportSettings _settings;
        private IDisposable _renewAuthenticationSubscription;
        public static async Task<ClientAuthenticatedTransport<T1>> CreateInstance(
            ClientAuthenticatedTransportSettings settings,
            ServerAuthenticatedFuncsForClient transport,
            Guid clientId,
            CancellationToken token,
            List<JsonRpcServerMethodInfo> methodInfos = null
        )
        {
            var result = new ClientAuthenticatedTransport<T1>();
            result._settings = settings;
            result._transport = transport;
            result._clientId = clientId;
            var getMethodInfosTask = await Task.Factory.StartNew(
                async () =>
                {
                    if (methodInfos == null)
                    {
                        while (true)
                        {
                            try
                            {
                                methodInfos =
                                    await transport.GetMethodInfos()
                                        .ThrowIfCancelled(token).ConfigureAwait(false);
                                break;
                            }
                            catch (TimeoutException)
                            {
                            }
                        }
                    }
                }
            ).ConfigureAwait(false);
            byte[] newAuthData = null;
            var getAuthDataTask = await Task.Factory.StartNew(
                async () =>
                {
                    while (true)
                    {
                        try
                        {
                            newAuthData =
                                await transport.GetAuthData(clientId)
                                .ThrowIfCancelled(token).ConfigureAwait(false);
                            break;
                        }
                        catch (TimeoutException)
                        {
                        }
                    }
                }
            ).ConfigureAwait(false);
            await getMethodInfosTask.ConfigureAwait(false);
            await getAuthDataTask.ConfigureAwait(false);
            if(methodInfos == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => methodInfos)
                );
            if(newAuthData == null)
                throw new ArgumentNullException(
                    MyNameof.GetLocalVarName(() => newAuthData)
                );
            if (
                !JsonRpcClientProcessor.CheckRpcServerMethodInfos(
                    typeof(T1),
                    methodInfos
                )
            )
                throw new Exception("Rpc server method infos not matches with T1");
            result._renewAuthenticationSubscription =
                Observable.Interval(settings.RenewAuthenticationInterval)
                    .ObserveOn(TaskPoolScheduler.Default).Subscribe(async i => await result.RenewAuthenticatedData().ConfigureAwait(false));
            result._stateHelper.SetInitializedState();
            await result.RenewAuthenticatedData(newAuthData).ConfigureAwait(false);
            return await Task.FromResult(result).ConfigureAwait(false);
        }

        private static readonly Logger _logger = LogManager.GetCurrentClassLogger();
        private readonly SemaphoreSlimSet _lockSemSet = new SemaphoreSlimSet();
        private DateTime _authValidUntil = DateTime.MinValue;
        private async void RenewAuthenticatedDataVoid(bool forceRenew = false)
        {
            await RenewAuthenticatedData(forceRenew: forceRenew).ConfigureAwait(false);
        }

        private async Task RenewAuthenticatedData(
            byte[] initAuthData = null,
            bool forceRenew = false
        )
        {
            try
            {
                using (_stateHelper.GetFuncWrapper())
                {
                    using (
                        await _lockSemSet.GetDisposable(
                            this.MyNameOfMethod(
                                e => e.RenewAuthenticatedData(null,false)
                            ),
                            true
                        ).ConfigureAwait(false)
                    )
                    {
                        //var ctsTask = _cts.Token.ToTask();
                        while (!_cts.IsCancellationRequested)
                        {
                            var nowTimeUtc = DateTime.UtcNow;
                            using (
                                await _lockSemSet.GetDisposable(
                                    this.MyNameOfProperty(
                                        e => e._authValidUntil
                                        )
                                    ).ConfigureAwait(false)
                                )
                            {
                                if (forceRenew)
                                {
                                    _authValidUntil = DateTime.MinValue;
                                }
                                else
                                {
                                    if (
                                        _authValidUntil
                                        > nowTimeUtc
                                        + AuthenticatedTransportCommonConstants
                                            .RenewBeforeEnd
                                    )
                                        return;
                                }
                            }
                            byte[] newAuthData;
                            if (initAuthData != null)
                            {
                                newAuthData = initAuthData;
                                initAuthData = null;
                            }
                            else
                            {
                                while (true)
                                {
                                    try
                                    {
                                        newAuthData =
                                            await _transport.GetAuthData(_clientId)
                                                .ThrowIfCancelled(_cts.Token).ConfigureAwait(false);
                                        break;
                                    }
                                    catch (TimeoutException)
                                    {
                                    }
                                }
                            }
                            nowTimeUtc = DateTime.UtcNow;
                            bool authMeResult;
                            byte[] hashHashAuthBytes;
                            using (var hashAlg = new SHA256Managed())
                            {
                                hashHashAuthBytes = hashAlg.ComputeHash(
                                    await _transport.DecryptAuthDataFunc(newAuthData).ConfigureAwait(false)
                                );
                            }
                            while (true)
                            {
                                try
                                {
                                    authMeResult =
                                        await _transport.AuthMe(
                                            _clientId,
                                            hashHashAuthBytes
                                            ).ThrowIfCancelled(_cts.Token).ConfigureAwait(false);
                                    break;
                                }
                                catch (TimeoutException)
                                {
                                }
                            }
                            if (
                                !authMeResult
                                )
                                continue;
                            using (
                                await _lockSemSet.GetDisposable(
                                    this.MyNameOfProperty(
                                        e => e._authValidUntil
                                        )
                                    ).ConfigureAwait(false)
                                )
                            {
                                _authValidUntil
                                    = nowTimeUtc
                                      + AuthenticatedTransportCommonConstants
                                          .DefaultAuthDuration;
                            }
                            return;
                        }
                    }
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (WrongDisposableObjectStateException)
            {
            }
            catch (Exception exc)
            {
                _logger.Error(
                    string.Format(
                        "RenewAuthenticatedData error '{0}'",
                        exc.ToString()
                    )
                );
            }
        }

        public void BeforeInvoke(InvocationInfo info)
        {
        }
        private async Task<object> DoInvokeImpl(InvocationInfo info)
        {
            using (_stateHelper.GetFuncWrapper())
            {
                var jsonRequest = JsonRpcClientProcessor.GetJsonRpcRequest(info);
                bool authFailedExceptionThrown = false;
                byte[] serverAnswerData = null;
                var nowTimeUtc = DateTime.UtcNow;

                DateTime nowAuthValidUntil;
                using (
                    await _lockSemSet.GetDisposable(
                        this.MyNameOfProperty(
                            e => e._authValidUntil
                        )
                    ).ConfigureAwait(false)
                )
                    nowAuthValidUntil = _authValidUntil;
                if (
                    nowAuthValidUntil
                        < nowTimeUtc
                        + AuthenticatedTransportCommonConstants
                            .RenewBeforeEnd
                    )
                {
                    RenewAuthenticatedDataVoid();
                    if (nowAuthValidUntil < nowTimeUtc)
                    {
                        await Task.Delay(
                            AuthenticatedTransportCommonConstants.TimeoutOnAuthFailed
                        ).ConfigureAwait(false);
                        throw new TimeoutException();
                    }
                }
                try
                {
                    serverAnswerData = await _transport.ProcessRequest(
                        Encoding.UTF8.GetBytes(jsonRequest.WriteObjectToJson()),
                        _clientId
                    ).ThrowIfCancelled(_cts.Token).ConfigureAwait(false);
                }
                catch (RpcRethrowableException rpcExc)
                {
                    if (
                        rpcExc.ErrorData.ErrorCode
                        == AuthenticatedTransportCommonConstants
                            .RpcRethrowableExceptionAuthFailedErrorCode
                    )
                    {
                        authFailedExceptionThrown = true;
                    }
                    else
                    {
                        throw;
                    }
                }
                if (authFailedExceptionThrown)
                {
                    RenewAuthenticatedDataVoid(true);
                    await Task.Delay(
                        AuthenticatedTransportCommonConstants.TimeoutOnAuthFailed
                    ).ConfigureAwait(false);
                    throw new TimeoutException();
                }
                if(serverAnswerData == null)
                    throw new ArgumentNullException(
                        MyNameof.GetLocalVarName(() => serverAnswerData)
                    );
                return await JsonRpcClientProcessor.GetJsonRpcResult(
                    JObject.Parse(
                        Encoding.UTF8.GetString(
                            serverAnswerData
                        )
                    ),
                    info
                ).ConfigureAwait(false);
            }
        }
        public object DoInvoke(InvocationInfo info)
        {
            return JsonRpcClientProcessor.DoInvokeHelper(info, DoInvokeImpl);
        }

        public void AfterInvoke(InvocationInfo info, object returnValue)
        {
        }

        private T1 _proxy = null;
        private readonly SemaphoreSlim _proxyLockSem = new SemaphoreSlim(1);
        public async Task<T1> GetClientProxy()
        {
            using (_stateHelper.GetFuncWrapper())
            {
                using (await _proxyLockSem.GetDisposable().ConfigureAwait(false))
                {
                    return _proxy 
                        ?? (_proxy = (new ProxyFactory()).CreateProxy<T1>(this));
                }
            }
        }
        private readonly DisposableObjectStateHelper _stateHelper
            = new DisposableObjectStateHelper("ClientAuthenticatedTransport");
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        public async Task MyDisposeAsync()
        {
            _cts.Cancel();
            await _stateHelper.MyDisposeAsync().ConfigureAwait(false);
            _renewAuthenticationSubscription.Dispose();
            _cts.Dispose();
        }
    }
}
