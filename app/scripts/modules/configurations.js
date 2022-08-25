angular.module('configurations', [])
    .constant('API_VERSION', '/fineract-provider/api/v1')
    .constant('IDLE_DURATION', 2 * 60)
    .constant('WARN_DURATION', 10)
    .constant('KEEPALIVE_INTERVAL', 3 * 60)
    .constant('SECURITY', 'oauth');
// Use SECURITY constant as 'oauth' to enable Oauth2 on community app
