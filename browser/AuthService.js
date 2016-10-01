angular.module('app')
  .factory('AuthService', function($http){

    var _user = {};
    return {
      user: _user,
      logout: function(){
        return $http.delete('/api/sessions')
        .then(function(){
          angular.copy({}, _user);
        });
      },
      me: function(){
        $http.get('/api/sessions')
          .then(function(result){
            angular.copy(result.data, _user);
          });
      
      },
      login: function(credentials){
        return $http.post('/api/sessions', credentials)
          .then(function(result){
            angular.copy(result.data, _user);
          });
      }
    };
  })
  .run(function(AuthService){
    AuthService.me();
  });
