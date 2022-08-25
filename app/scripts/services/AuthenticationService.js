(function (module) {
    mifosX.services = _.extend(module, {
        AuthenticationService: function (scope, httpService, SECURITY, localStorageService,timeout, webStorage) {
            var userData = null;
            var twoFactorIsRememberMeRequest = false;
            var twoFactorAccessToken = null;

            var onLoginSuccess = function (response) {
                var data = response.data;
                localStorageService.addToLocalStorage('tokendetails', {
                        "expires_in": data.expiresIn,
                        "access_token": data.accessToken,
                        "refresh_token": data.refreshToken
                    }
                );
                setTimer(data.expires_in);
                if(data.isTwoFactorAuthenticationRequired != null && data.isTwoFactorAuthenticationRequired == true) {
                    if(hasValidTwoFactorToken(data.username)) {
                        var token = getTokenFromStorage(data.username);
                        onTwoFactorRememberMe(data, token);
                    } else {
                        userData = data;
                        scope.$broadcast("UserAuthenticationTwoFactorRequired", data);
                    }
                } else {
                    scope.$broadcast("UserAuthenticationSuccessEvent", data);
                    localStorageService.addToLocalStorage('userData', data);
                }
            };

            var onLoginFailure = function (response) {
                var data = response.data;
                var status = response.status;
                scope.$broadcast("UserAuthenticationFailureEvent", data, status);
            };

            var apiVer = '/fineract-provider/api/v1';

            var updateAccessDetails = function(response){
                var data = response.data;
                var sessionData = webStorage.get('sessionData');
                sessionData.authenticationKey = data.access_token;
                webStorage.add("sessionData",sessionData);
                localStorageService.addToLocalStorage('tokendetails', data);
                var userDate = localStorageService.getFromLocalStorage("userData");
                userDate.accessToken =  data.access_token;
                localStorageService.addToLocalStorage('userData', userDate);
                httpService.setAuthorization(data.access_token);
                setTimer(data.expires_in);
            }

            var setTimer = function(time){
                timeout(getAccessToken, time * 1000);
            }

            var getAccessToken = function(){
                var refreshToken = localStorageService.getFromLocalStorage("tokendetails").refresh_token;
                //httpService.cancelAuthorization();
                //TODO:- Innocent implement refresh token logic
                // httpService.post( "/fineract-provider/api/oauth/token?&client_id=community-app&grant_type=refresh_token&client_secret=123&refresh_token=" + refreshToken)
                //     .then(updateAccessDetails);
                //TODO: - Innocent logout user when there couldn't get token
            }

            this.authenticateWithUsernamePassword = function (credentials) {
                scope.$broadcast("UserAuthenticationStartEvent");
        		if(SECURITY === 'oauth'){
                    httpService.post(apiVer + "/authentication", { "username": credentials.username, "password": credentials.password})
	                // httpService.post( "/fineract-provider/api/oauth/token?username=" + credentials.username + "&password=" + credentials.password +"&client_id=community-app&grant_type=password&client_secret=123")
                    .then(onLoginSuccess)
                    .catch(onLoginFailure);
        		} else {
                    httpService.post(apiVer + "/authentication", { "username": credentials.username, "password": credentials.password})
                    .then(onLoginSuccess)
                    .catch(onLoginFailure);
        		}
            };

            var onTwoFactorRememberMe = function (userData, tokenData) {
                var accessToken = tokenData.token;
                twoFactorAccessToken = accessToken;
                httpService.setTwoFactorAccessToken(accessToken);
                scope.$broadcast("UserAuthenticationSuccessEvent", userData);
                localStorageService.addToLocalStorage('userData', userData);
            };

            var onOTPValidateSuccess = function (response) {
                var data = response.data;
                var accessToken = data.token;
                if(twoFactorIsRememberMeRequest) {
                    saveTwoFactorTokenToStorage(userData.username, data);
                }
                twoFactorAccessToken = accessToken;
                httpService.setTwoFactorAccessToken(accessToken);
                scope.$broadcast("UserAuthenticationSuccessEvent", userData);
                localStorageService.addToLocalStorage('userData', userData);
            };

            var onOTPValidateError = function (response) {
                var data = response.data;
                var status = response.status;
                scope.$broadcast("TwoFactorAuthenticationFailureEvent", data, status);
            };

            var getTokenFromStorage = function (user) {
                var twoFactorStorage = localStorageService.getFromLocalStorage("twofactor");

                if(twoFactorStorage) {
                    return twoFactorStorage[user]
                }
                return null;
            };

            var saveTwoFactorTokenToStorage = function (user, tokenData) {
                var storageData = localStorageService.getFromLocalStorage("twofactor");
                if(!storageData) {
                    storageData = {}
                }
                storageData[user] = tokenData;
                localStorageService.addToLocalStorage('twofactor', storageData);
            };

            var removeTwoFactorTokenFromStorage = function (username) {
                var storageData = localStorageService.getFromLocalStorage("twofactor");
                if(!storageData) {
                    return;
                }

                delete storageData[username]
                localStorageService.addToLocalStorage('twofactor', storageData);
            };

            var hasValidTwoFactorToken = function (user) {
                var token = getTokenFromStorage(user);
                if(token) {
                    return (new Date).getTime() + 7200000 < token.validTo;
                }
                return false;
            };

            this.validateOTP = function (token, rememberMe) {
                twoFactorIsRememberMeRequest = rememberMe;
                httpService.post(apiVer + "/twofactor/validate?token=" + token)
                    .then(onOTPValidateSuccess)
                    .catch(onOTPValidateError);
            };

            scope.$on("OnUserPreLogout", function (event) {
                var userDate = localStorageService.getFromLocalStorage("userData");

                // Remove user data and two-factor access token if present
                localStorageService.removeFromLocalStorage("userData");
                removeTwoFactorTokenFromStorage(userDate.username);

                httpService.post(apiVer + "/twofactor/invalidate", '{"token": "' + twoFactorAccessToken + '"}');
            });
        }
    });
    mifosX.ng.services.service('AuthenticationService', ['$rootScope', 'HttpService', 'SECURITY', 'localStorageService','$timeout','webStorage', mifosX.services.AuthenticationService]).run(function ($log) {
        $log.info("AuthenticationService initialized");
    });
}(mifosX.services || {}));
