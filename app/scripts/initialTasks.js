
(function (mifosX) {
    var defineHeaders = function ($httpProvider, $translateProvider, ResourceFactoryProvider, HttpServiceProvider, $idleProvider, $keepaliveProvider, IDLE_DURATION, WARN_DURATION, KEEPALIVE_INTERVAL) {
        var baseApiUrl = "https://localhost:8443/fineract-provider";
        var host = "";

        var queryLink = getLocation(baseApiUrl);
        host = "https://" + queryLink.hostname + (queryLink.port ? ':' + queryLink.port : '');

        $httpProvider.defaults.headers.common['Fineract-Platform-TenantId'] = 'default';
        ResourceFactoryProvider.setTenantIdenetifier('default');
        ResourceFactoryProvider.setBaseUrl(host);
        HttpServiceProvider.addRequestInterceptor('demoUrl', function (config) {
            return _.extend(config, {url: host + config.url });
        });

        // Enable CORS! (see e.g. http://enable-cors.org/)
        $httpProvider.defaults.useXDomain = true;
        delete $httpProvider.defaults.headers.common['X-Requested-With'];

        //Set headers
        $httpProvider.defaults.headers.common['Content-Type'] = 'application/json; charset=utf-8';

        // Configure i18n and preffer language
        //$translateProvider.translations('en', translationsEN);
        //$translateProvider.translations('de', translationsDE);
        $translateProvider.useSanitizeValueStrategy('escaped');
        $translateProvider.useStaticFilesLoader({
            prefix: 'global-translations/locale-',
            suffix: '.json'
        });

        $translateProvider.preferredLanguage('en');
        $translateProvider.fallbackLanguage('en');
        //Timeout settings.
        $idleProvider.idleDuration(IDLE_DURATION); //Idle time 
        $idleProvider.warningDuration(WARN_DURATION); //warning time(sec)
        $keepaliveProvider.interval(KEEPALIVE_INTERVAL); //keep-alive ping
    };
    mifosX.ng.application.config(defineHeaders).run(function ($log, $idle) {
        $log.info("Initial tasks are done!");
        $idle.watch();
    });
}(mifosX || {}));

getLocation = function (href) {
    var l = document.createElement("a");
    l.href = href;
    return l;
};

QueryParameters = (function () {
    var result = {};
    if (window.location.search) {
        // split up the query string and store in an associative array
        var params = window.location.search.slice(1).split("&");
        for (var i = 0; i < params.length; i++) {
            var tmp = params[i].split("=");
            result[tmp[0]] = unescape(tmp[1]);
        }
    }
    return result;
}());
